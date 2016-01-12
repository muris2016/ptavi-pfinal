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
import uaserver
from uaserver import write_log


class BadRequest(Exception):
    error = "SIP/2.0 400 Bad Request\r\n\r\n"

class UserNotFound(Exception):
    error = "SIP/2.0 404 User Not Found\r\n\r\n"

class MethodNotAllowed(Exception):
    error = "SIP/2.0 405 Method Not Allowed\r\n\r\n"

class AddressIncomplete(Exception):
    error = "SIP/2.0 484 Address Incomplete\r\n\r\n"



def take_args():
    if len(sys.argv) != 2:
        sys.exit('Usage: python3 proxy_registrar.py config')
    else:
        return sys.argv[1]


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


def check_format(client_address, line):
    ip = client_address[0]
    port = client_address[1]
    write_log(config_dict, 'Received from', ip, port, line)

    try:
        method = line.split()[0]
        sip_login = line.split()[1]
        sip_version = line.split()[2]
        if (not 'sip:' in sip_login or sip_version != 'SIP/2.0'):
            raise BadRequest
        return method, ip, port
    except:
        raise BadRequest


def is_valid_ip(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:
        return False

    return True


def check_register(line):
    try:
        login = line.split()[1].split(':')[1]
        port_uas = int(line.split()[1].split(':')[2])
        expires = int(line.split()[4])
    except:
        raise BadRequest

    return login, port_uas, expires


def check_invite(line, users_dict):
    dest_login = line.split()[1].split('sip:')[1]
    origin_login = line.split('o=')[1].split()[0]
    if not origin_login in users_dict or not dest_login in users_dict:
        raise UserNotFound



def is_valid_sdp(line, sending_rtp_dict):
    content_type = line.split('Content-Type: ')[1].split()[0]
    version = int(line.split('v=')[1].split()[0])
    origin = line.split('o=')[1].split()[0:2]
    sesion = line.split('s=')[1].split()[0]
    time = int(line.split('t=')[1].split()[0])
    media = line.split('m=')[1].split()
    media[1] = int(media[1])

    if not is_valid_ip(origin[1]):
        raise AddressIncomplete

    if (content_type != 'application/sdp' or version != 0
            or not is_valid_ip(origin[1]) or time != 0 or media[0] != 'audio'
            or media[2] != 'RTP'):

        sending_rtp_dict['ua1'] = origin
        return False
    else:
        return True


def sent_to_uaserver(line):
    login = line.split()[1].split(':')[1]
    users_dict = file2dict(database_path)
    if not login in users_dict:
        raise UserNotFound

    ip_to_send = users_dict[login]['ip']
    port_to_send = int(users_dict[login]['port'])

    via_proxy = "Via: SIP/2.0/UDP " + '127.0.0.1' + ':' + str(5080) + ';rport;' + 'branch=' + str(random.randint(100000000, 850000000)) + '\r\n'
    line = line.replace('\r\n', '\r\n' + via_proxy, 1)

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
    sending_rtp_dict = {'ua1': '', 'ua2': ''}

    def handle(self):
        error_occurred = True
        self.users_dict = file2dict(database_path)
        clean_clients(self.users_dict)
        methods = {'REGISTER': self.register, 'INVITE': self.invite}
        methods.update({'ACK': self.ack, 'BYE': self.bye})
        while 1:
            line = self.rfile.read().decode('utf-8')
            if not line:
                break
            # print(line)
            method, ip, port = check_format(self.client_address, line)
            try:
                if not method in methods:
                    raise MethodNotAllowed
                else:
                    methods[method](line, ip, port)
                    error_occurred = False

            except MethodNotAllowed:
                msg = MethodNotAllowed.error
            except BadRequest:
                msg = BadRequest.error
            except UserNotFound:
                msg = UserNotFound.error
            except AddressIncomplete:
                msg = AddressIncomplete.error
            except ConnectionRefusedError:
                msg = "SIP/2.0 603 Decline\r\n\r\n"

            if error_occurred:
                self.wfile.write(msg.encode('utf-8'))
                write_log(config_dict, 'Sent to', ip, port, msg)

    def register(self, line, ip, port):
        login, port_uas, expires = check_register(line)
        passwd_dict = file2dict(passwdpath)

        if not login in passwd_dict:
            raise UserNotFound

        elif not 'Authorization:' in line:
            nonce = str(random.randrange(10**22))
            passwd_dict[login]['last_nonce'] = nonce
            dict2file(passwdpath, passwd_dict)
            msg = 'SIP/2.0 401 Unauthorized\r\n'
            msg += 'WWW-Authenticate: Digest nonce="%s"\r\n\r\n' % (nonce)

        else:
            nonce = passwd_dict[login]['last_nonce']
            passwd = passwd_dict[login]['passwd']
            response = uaclient.get_hash(nonce, passwd)
            user_response = line.split('=')[-1].split()[0].strip('"')
            if user_response == response:
                msg = 'SIP/2.0 200 OK\r\n\r\n'
                if expires != 0:
                    exp_t = expires + time.time()
                    self.users_dict[login] = {'ip': ip, 'port': port_uas,
                                              'register date': time.time(),
                                              'expires date': exp_t}
                else:
                    if login in self.users_dict:
                        del self.users_dict[login]
            else:
                msg = 'SIP/2.0 401 Unauthorized\r\n\r\n'

            dict2file(database_path, self.users_dict)

        self.wfile.write(msg.encode('utf-8'))
        write_log(config_dict, 'Sent to', ip, port, msg)

    def invite(self, line, ip, port):
        check_invite(line, self.users_dict)

        if is_valid_sdp(line, self.sending_rtp_dict):
            data = sent_to_uaserver(line)
            # if not is_valid_sdp(data):
            #     data = BadRequest.error

            self.wfile.write(bytes(data, 'utf-8'))
            write_log(config_dict, 'Sent to', ip, port, data)
        else:
            raise BadRequest

    def ack(self, line, ip, port):
        sent_to_uaserver(line)

    def bye(self, line, ip, port):
        data = sent_to_uaserver(line)
        self.wfile.write(bytes(data, 'utf-8'))
        write_log(config_dict, 'Sent to', ip, port, data)


def main():
    global config_dict, passwdpath, database_path
    config = take_args()
    config_dict = uaserver.get_tags(config, uaserver.ConfigHandler, proxy=True)
    passwdpath = config_dict['database']['passwdpath']
    database_path = config_dict['database']['path']
    name_server = config_dict['server']['name']
    port = int(config_dict['server']['puerto'])

    return name_server, port


if __name__ == '__main__':
    name_server, port = main()
    write_log(config_dict, 'Starting')
    print('Server %s listening at port %s' % (name_server, port))
    serv = socketserver.UDPServer(('', port), SIPPRHandler)
    serv.serve_forever()
    write_log(config_dict, 'Finishing\n\r')
