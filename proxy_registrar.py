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
from uaserver import write_log
import uaserver


class SipCodeException(Exception):
    codes = {200: '200 OK', 400: '400 Bad Request',
             401: '401 Unauthorized', 403: '403 Forbidden',
             404: '404 User Not Found', 405: '405 Method Not Allowed',
             409: '409 Conflict', 480: '480 Temporarily Unavailable',
             484: '484 Address Incomplete', 603: '603 Decmsg_recv'}

    def __init__(self, code):
        self.code = 'SIP/2.0 %s\r\n\r\n' % (self.codes[code])


def file2dict(filename):
    try:
        with open(filename, 'r') as outfile:
            json_str = outfile.read()
            return json.loads(json_str)
    except:
        return {}


def dict2file(filename, dict):
    with open(filename, 'w') as outfile:
        json.dump(dict, outfile, sort_keys=True, indent=4)


def clean_clients(users_dict):
    clean_list = [client for client in users_dict
                  if users_dict[client]['expires date'] < time.time()]
    for client in clean_list:
        del users_dict[client]


def get_hash(nonce, passwd):
    m = hashlib.md5()
    m.update(nonce.encode('utf-8'))
    m.update(passwd.encode('utf-8'))
    return m.hexdigest()


def msg_info(client_address, msg_recv):
    ip = client_address[0]
    port = client_address[1]
    write_log(config_dict, 'Received from', ip, port, msg_recv)
    return ip, port


def check_format(msg_recv):
    try:
        method = msg_recv.split()[0]
        sip_login = msg_recv.split()[1]
        sip_version = msg_recv.split()[2]
    except:
        raise SipCodeException(400)

    if (not 'sip:' in sip_login or sip_version != 'SIP/2.0'):
        raise SipCodeException(400)
    return method


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


def check_register(msg_recv):
    try:
        login = msg_recv.split()[1].split(':')[1]
        port_uas = int(msg_recv.split()[1].split(':')[2])
        expires = int(msg_recv.split('Expires:')[1])
    except:
        raise SipCodeException(400)
    return login, port_uas, expires


def check_invite(msg_recv, users_dict, sending_rtp_dict):
    try:
        origin_login = msg_recv.split('o=')[1].split()[0]
        dest_login = msg_recv.split()[1].split('sip:')[1]
    except:
        raise SipCodeException(400)

    if not origin_login in users_dict:
        raise SipCodeException(401)
    elif not dest_login in users_dict:
        raise SipCodeException(404)
    else:
        sending_rtp_dict[origin_login] = dest_login
        sending_rtp_dict[dest_login] = origin_login


def is_valid_sdp(msg_recv):
    valid = True
    try:
        content_type = msg_recv.split('Content-Type: ')[1].split()[0]
        version = int(msg_recv.split('v=')[1].split()[0])
        origin = msg_recv.split('o=')[1].split()[0:2]
        sesion = msg_recv.split('s=')[1].split()[0]
        time = int(msg_recv.split('t=')[1].split()[0])
        media = msg_recv.split('m=')[1].split()
        media[1] = int(media[1])
    except:
        raise SipCodeException(400)

    if not is_valid_ip(origin[1]):
        raise SipCodeException(484)

    if (content_type != 'application/sdp' or version != 0 or time != 0
            or media[0] != 'audio' or media[2] != 'RTP'):
        valid = False

    return valid


def is_valid_bye(msg_recv, ip, sending_rtp_dict):
    valid = False
    peer1 = msg_recv.split()[1].split('sip:')[1]
    if peer1 in sending_rtp_dict:
        peer2 = sending_rtp_dict[peer1]
        del sending_rtp_dict[peer1]
        del sending_rtp_dict[peer2]
        valid = True
    return valid


def add_proxy_header(msg_recv):
    ip = config_dict['server']['ip']
    port = config_dict['server']['puerto']
    branch = random.randrange(10**20)
    via = '\r\nVia: SIP/2.0/UDP %s:%s;branch=%s;rport\r\n' % (ip, port, branch)
    msg_recv = msg_recv.replace('\r\n', via, 1)
    return msg_recv


def sent_to_uaserver(msg_recv, users_dict):
    login = msg_recv.split()[1].split(':')[1]
    if not login in users_dict:
        raise SipCodeException(404)

    ip_to_send = users_dict[login]['ip']
    port_to_send = int(users_dict[login]['port'])

    msg_recv = add_proxy_header(msg_recv)
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.connect((ip_to_send, port_to_send))
    my_socket.send(bytes(msg_recv, 'utf-8'))
    write_log(config_dict, 'Sent to', ip_to_send, port_to_send, msg_recv)

    try:
        data = my_socket.recv(1024).decode('utf-8')
        my_socket.close()
    except:
        my_socket.close()
        raise SipCodeException(603)

    write_log(config_dict, 'Received from', ip_to_send, port_to_send, data)
    data = add_proxy_header(data)
    return data


class SIPPRHandler(socketserver.DatagramRequestHandler):

    users_dict = {}
    sending_rtp_dict = {}

    def handle(self):
        error_occurred = True
        self.users_dict = file2dict(database_path)
        clean_clients(self.users_dict)
        methods = {'REGISTER': self.register, 'INVITE': self.invite,
                   'ACK': self.ack, 'BYE': self.bye}
        while 1:
            msg_recv = self.rfile.read().decode('utf-8')
            if not msg_recv:
                break
            ip, port = msg_info(self.client_address, msg_recv)
            try:
                method = check_format(msg_recv)
                if not method in methods:
                    raise SipCodeException(405)
                else:
                    print(method, 'received')
                    methods[method](msg_recv, ip, port)
                    error_occurred = False

            except SipCodeException as sipcode:
                msg = sipcode.code

            if error_occurred:
                self.wfile.write(msg.encode('utf-8'))
                write_log(config_dict, 'Sent to', ip, port, msg)

            dict2file(database_path, self.users_dict)

    def register(self, msg_recv, ip, port):
        login, port_uas, expires = check_register(msg_recv)
        passwd_dict = file2dict(passwdpath)

        if not login in passwd_dict:
            raise SipCodeException(404)

        elif not 'Authorization:' in msg_recv:
            nonce = str(random.randrange(10**22))
            passwd_dict[login]['last_nonce'] = nonce
            dict2file(passwdpath, passwd_dict)
            msg = 'SIP/2.0 401 Unauthorized\r\n'
            msg += 'WWW-Authenticate: Digest nonce="%s"\r\n\r\n' % (nonce)

        else:
            nonce = passwd_dict[login]['last_nonce']
            passwd = passwd_dict[login]['passwd']
            response = get_hash(nonce, passwd)
            user_response = msg_recv.split('=')[-1].split()[0].strip('"')
            if user_response != response:
                raise SipCodeException(401)

            msg = 'SIP/2.0 200 OK\r\n\r\n'
            if expires != 0:
                if login in self.users_dict:
                    raise SipCodeException(409)
                exp_t = expires + time.time()
                self.users_dict[login] = {'ip': ip, 'port': port_uas,
                                          'register date': time.time(),
                                          'expires date': exp_t}
            elif expires == 0:
                if login in self.users_dict:
                    del self.users_dict[login]

        self.wfile.write(msg.encode('utf-8'))
        write_log(config_dict, 'Sent to', ip, port, msg)

    def invite(self, msg_recv, ip, port):
        check_invite(msg_recv, self.users_dict, self.sending_rtp_dict)
        if is_valid_sdp(msg_recv):
            data = sent_to_uaserver(msg_recv, self.users_dict)
            self.wfile.write(bytes(data, 'utf-8'))
            write_log(config_dict, 'Sent to', ip, port, data)
        else:
            raise SipCodeException(400)

    def ack(self, msg_recv, ip, port):
        sent_to_uaserver(msg_recv, self.users_dict)

    def bye(self, msg_recv, ip, port):
        if is_valid_bye(msg_recv, ip, self.sending_rtp_dict):
            data = sent_to_uaserver(msg_recv, self.users_dict)
            self.wfile.write(bytes(data, 'utf-8'))
            write_log(config_dict, 'Sent to', ip, port, data)

        else:
            raise SipCodeException(403)


def main():
    if len(sys.argv) != 2:
        sys.exit('Usage: python3 proxy_registrar.py config')
    else:
        config = sys.argv[1]
    global config_dict, passwdpath, database_path
    config_dict = uaserver.get_tags(config, uaserver.ConfigHandler, proxy=True)
    passwdpath = config_dict['database']['passwdpath']
    database_path = config_dict['database']['path']
    name_server = config_dict['server']['name']
    ip = config_dict['server']['ip']
    port = int(config_dict['server']['puerto'])
    return name_server, ip, port


if __name__ == '__main__':
    name_server, ip, port = main()
    write_log(config_dict, 'Starting')
    print('Server %s listening at port %s' % (name_server, port))
    serv = socketserver.UDPServer((ip, port), SIPPRHandler)
    serv.serve_forever()
    write_log(config_dict, 'Finishing\n\r')
