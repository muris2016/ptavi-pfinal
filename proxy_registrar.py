#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import socketserver
import socket
import random
import json
import hashlib
import time
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import uaclient
from uaclient import write_log


class ConfigPRHandler(uaclient.ConfigUAHandler):
    def __init__(self):

        self.labels = {'server': {'name': '', 'ip': '', 'puerto': ''},
                       'database': {'path': '', 'passwdpath': ''},
                       'log': {'path': ''}}

        self.config_dict = {}

config_dict = uaclient.get_tags('pr.xml', ConfigPRHandler)
passwdpath = config_dict['database']['passwdpath']
database_path = config_dict['database']['path']


def file2dict(filename):
    with open(filename, 'r') as outfile:
        json_str = outfile.read()
        return json.loads(json_str)


def dict2file(filename, dict):
    with open(filename, 'w') as outfile:
        json.dump(dict, outfile, sort_keys=True, indent=4)


def clean_clients(users_dict):
    clean_list = [client for client in users_dict
                  if users_dict[client]['expires date'] < time.time()]
    for client in clean_list:
        del users_dict[client]


def sent_to_uaserver(line):
    login = line.split()[1].split(':')[1]
    users_dict = file2dict(database_path)
    ip_to_send = users_dict[login]['ip']
    port_to_send = int(users_dict[login]['port'])

    my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.connect((ip_to_send, port_to_send))
    my_socket.send(bytes(line, 'utf-8'))
    write_log(config_dict, 'Sent to', ip_to_send, port_to_send, line)
    data = my_socket.recv(1024).decode('utf-8')
    my_socket.close()

    write_log(config_dict, 'Received from', ip_to_send, port_to_send, data)
    return data


class SIPPRHandler(socketserver.DatagramRequestHandler):

    users_dict = {}

    def handle(self):
        error_occurred = True
        self.users_dict = file2dict(database_path)
        clean_clients(self.users_dict)
        self.methods = {'REGISTER': self.register, 'INVITE': self.invite}
        self.methods['ACK'] = self.ack
        self.methods['BYE'] = self.bye
        while 1:
            line = self.rfile.read().decode('utf-8')
            if not line:
                break
            ip = self.client_address[0]
            port = self.client_address[1]
            write_log(config_dict, 'Received from', ip, port, line)
            method = line.split()[0]
            sip_login = line.split()[1]
            sip_version = line.split()[2]
            if (not 'sip:' in sip_login or sip_version != 'SIP/2.0'):
                msg = "SIP/2.0 400 Bad Request\r\n\r\n"
                break
            try:
                self.methods[method](line, ip, port)
                error_occurred = False
            except KeyError:
                msg = "SIP/2.0 405 Method Not Allowed\r\n\r\n"
            except IndexError:
                msg = "SIP/2.0 404 User Not Found\r\n\r\n"
            except:
                print("Error inesperado:", sys.exc_info()[0])

        if error_occurred:
            self.wfile.write(msg.encode('utf-8'))
            write_log(config_dict, 'Sent to', ip, port, msg)
        dict2file(database_path, self.users_dict)

    def register(self, line, ip, port):
        login = line.split()[1].split(':')[1]
        port_uas = line.split()[1].split(':')[2]
        passwd_dict = file2dict(passwdpath)

        if not 'Authorization: response=' in line:
            nonce = str(random.randrange(10**22))
            passwd_dict[login]['last_nonce'] = nonce
            dict2file(passwdpath, passwd_dict)
            msg = 'SIP/2.0 401 Unauthorized\r\n'
            msg += 'WWW Authenticate: nonce=%s\r\n\r\n' % (nonce)

        else:
            nonce = passwd_dict[login]['last_nonce']
            passwd = passwd_dict[login]['passwd']
            response = uaclient.get_hash(nonce, passwd)
            user_response = line.split('=')[-1].split()[0]

            if user_response == response:
                msg = 'SIP/2.0 200 OK\r\n\r\n'
                expires = int(line.split()[4])
                exp_t = expires + time.time()
                self.users_dict[login] = {'ip': ip, 'port': port_uas,
                                          'resgritation date': time.time(),
                                          'expires date': exp_t}
            else:
                msg = 'SIP/2.0 401 Unauthorized\r\n\r\n'

        self.wfile.write(msg.encode('utf-8'))
        write_log(config_dict, 'Sent to', ip, port, msg)

    def invite(self, line, ip, port):
        data = sent_to_uaserver(line)
        self.wfile.write(bytes(data, 'utf-8'))
        write_log(config_dict, 'Sent to', ip, port, data)

    def ack(self, line, ip, port):
        sent_to_uaserver(line)

    def bye(self, line, ip, port):
        data = sent_to_uaserver(line)
        self.wfile.write(bytes(data, 'utf-8'))
        write_log(config_dict, 'Sent to', ip, port, data)

if __name__ == '__main__':
    write_log(config_dict, 'Starting...')
    name_server = config_dict['server']['name']
    port = int(config_dict['server']['puerto'])
    print('Server %s listening at port %s...' % (name_server, port))
    serv = socketserver.UDPServer(('', port), SIPPRHandler)
    serv.serve_forever()
    write_log(config_dict, 'Finishing...\n\r')
