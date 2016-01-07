#!/usr/bin/python
# -*- coding: utf-8 -*-

import socketserver
import socket
import random
import json
import hashlib
import time
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from uaclient import ConfigUAHandler
from uaclient import get_tags
from uaclient import get_hash

DATE_F = '%Y-%m-%d %H:%M:%S +0100'


class ConfigPRHandler(ConfigUAHandler):
    def __init__(self):

        self.labels = {'server': {'name': '', 'ip': '', 'puerto': ''},
                       'database': {'path': '', 'passwdpath': ''},
                       'log': {'path': ''}}

        self.conf_ua_dict = {}

conf_ua_dict = get_tags('pr.xml', ConfigPRHandler)
passwdpath = conf_ua_dict['database']['passwdpath']
database_path = conf_ua_dict['database']['path']


def file2dict(filename):
    with open(filename, 'r') as outfile:
        json_str = outfile.read()
        return json.loads(json_str)


def dict2file(filename, dict):
    with open(filename, 'w') as outfile:
        json.dump(dict, outfile, sort_keys=True, indent=4)


def clean_clients(users_dict):
    clean_list = [client for client in users_dict
                  if users_dict[client]["expires date"] < time.time()]
    for client in clean_list:
        del users_dict[client]


def sent_to_uaserver(line, my_socket):
    login = line.split()[1].split(':')[1]
    users_dict = file2dict(database_path)
    ip_to_send = users_dict[login]['ip']
    port_to_send = int(users_dict[login]['port'])

    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.connect((ip_to_send, port_to_send))
    my_socket.send(bytes(line, 'utf-8'))


class SIPPRHandler(socketserver.DatagramRequestHandler):

    users_dict = {}

    def handle(self):
        self.users_dict = file2dict(database_path)
        clean_clients(self.users_dict)
        self.methods = {"REGISTER": self.register, "INVITE": self.invite, "ACK": self.ack, "BYE": self.bye}
        ip = self.client_address[0]
        port = self.client_address[1]
        # print (ip, port, "wrote:")
        while 1:
            line = self.rfile.read().decode('utf-8')
            if not line:
                break
            method = line.split()[0]
            # try:
            self.methods[method](line, ip)
            dict2file(database_path, self.users_dict)
            # except:
            #     print("Usage: python uaclient.py config method option")

    def register(self, line, ip):
        print("Recivo register")
        print(line)
        login = line.split()[1].split(':')[1]
        port_uas = line.split()[1].split(':')[2]
        passwd_dict = file2dict(passwdpath)

        if not 'Authorization: response=' in line:
            nonce = str(random.randrange(10**22))
            passwd_dict[login]['last_nonce'] = nonce
            dict2file(passwdpath, passwd_dict)
            msg = 'SIP/2.0 401 Unauthorized\r\n'
            msg += 'WWW Authenticate: nonce=' + nonce + '\r\n\r\n'

            self.wfile.write(msg.encode('utf-8'))
        else:
            nonce = passwd_dict[login]['last_nonce']
            passwd = passwd_dict[login]['passwd']
            response = get_hash(nonce, passwd)
            user_response = line.split('=')[-1].split()[0]

            if user_response == response:
                self.wfile.write(b"SIP/2.0 200 OK\r\n\r\n")
                expires = int(line.split()[4])
                exp_t = expires + time.time()
                self.users_dict[login] = {'ip': ip, 'port': port_uas,
                                          'resgritation date': time.time(),
                                          'expires date': exp_t}
            else:
                self.wfile.write(b"SIP/2.0 400 BAD REQUEST\r\n\r\n")

    def invite(self, line, ip):
        print("Recivo inivite")
        print(line)

        my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sent_to_uaserver(line, my_socket)

        data = my_socket.recv(1024).decode('utf-8')
        self.wfile.write(bytes(data, 'utf-8'))
        my_socket.close()

    def ack(self, line, ip):
        print("recibooo ACK")
        print(line)
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sent_to_uaserver(line, my_socket)
        my_socket.close()

    def bye(self, line, ip):
        print("recibooo ACK")
        print(line)
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sent_to_uaserver(line, my_socket)

        data = my_socket.recv(1024).decode('utf-8')
        self.wfile.write(bytes(data, 'utf-8'))
        my_socket.close()

if __name__ == "__main__":
    port = int(conf_ua_dict['server']['puerto'])
    serv = socketserver.UDPServer(('', port), SIPPRHandler)
    serv.serve_forever()
