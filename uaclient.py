#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import os
import socket
import hashlib
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import time


class ConfigUAHandler(ContentHandler):
    def __init__(self):
        self.labels = {'account': {'username': '', 'passwd': ''},
                       'uaserver': {'ip': '', 'puerto': ''},
                       'rtpaudio':  {'puerto': ''},
                       'regproxy': {'ip': '', 'puerto': ''},
                       'log': {'path': ''}, 'audio': {'path': ''}}

        self.config_dict = {}

    def startElement(self, name, attrs):
        if name in self.labels:
            my_dict = {key: attrs.get(key, '') for key in self.labels[name]}
            self.config_dict[name] = my_dict


def write_log(config_dict, event, ip='', port='', msg=''):
    log_path = config_dict['log']['path']
    msg = ' '.join(msg.split())
    with open(log_path, 'a') as outfile:
        hour = str(time.strftime('%Y%m%d%H%M%S', time.gmtime()))
        if ip != '' and msg != '':
            outfile.write('%s %s %s:%s: %s\n' % (hour, event, ip, port, msg))
        elif ip == '':
            outfile.write('%s %s\n' % (hour, event))


def get_tags(config, Handler):
    parser = make_parser()
    cHandler = Handler()
    parser.setContentHandler(cHandler)
    parser.parse(open(config))
    return cHandler.config_dict


def take_args():
    if len(sys.argv) != 4:
        sys.exit('Usage: python uaclient.py config method option')
    else:
        return sys.argv[1], sys.argv[2], sys.argv[3]


def get_hash(nonce, passwd):
    m = hashlib.md5()
    m.update(nonce.encode('utf-8'))
    m.update(passwd.encode('utf-8'))
    return m.hexdigest()


def connect_to_proxy(msg, my_socket, config_dict):
    ip_server = config_dict['regproxy']['ip']
    port = int(config_dict['regproxy']['puerto'])

    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.connect((ip_server, port))
    my_socket.send(bytes(msg, 'utf-8'))

    write_log(config_dict, 'Sent to', ip_server, port, msg)
    data = my_socket.recv(1024).decode('utf-8')
    write_log(config_dict, 'Received from', ip_server, port, data)
    return data


def register(my_socket, config_dict, expires):
    write_log(config_dict, 'Starting...')
    expires = int(expires)
    username = config_dict['account']['username']
    port_uas = int(config_dict['uaserver']['puerto'])
    msg = 'REGISTER sip:%s:%s SIP/2.0\r\n' % (username, port_uas)
    msg += 'Expires: %s\r\n' % (expires)
    data = connect_to_proxy(msg, my_socket, config_dict)

    if 'Unauthorized' in data.split():
        nonce = data.split()[-1].split('=')[-1]
        passwd = config_dict['account']['passwd']
        response = get_hash(nonce, passwd)
        msg = 'REGISTER sip:%s:%s SIP/2.0\r\n' % (username, port_uas)
        msg += 'Expires: %s\r\n' % (expires)
        msg += 'Authorization: response=%s\r\n\r\n' % (response)
        data = connect_to_proxy(msg, my_socket, config_dict)


def invite(my_socket, config_dict, login):
    username = config_dict['account']['username']
    rtpaudio_port = config_dict['rtpaudio']['puerto']
    msg = 'INVITE sip:%s SIP/2.0\r\n' % (login)
    msg += 'Content-Type: application/sdp\r\n\r\n'
    msg += 'v=0\r\no=%s 127.0.0.1\r\ns=mp3p2p\r\nt=0\r\n' % (username)
    msg += 'm=audio %s RTP\r\n\r\n' % (rtpaudio_port)
    data = connect_to_proxy(msg, my_socket, config_dict)

    if '100 Trying' in data and '180 Ring' and data and '200 OK' in data:
        msg = 'ACK sip:%s SIP/2.0\r\n\r\n' % (login)
        connect_to_proxy(msg, my_socket, config_dict)

        rtp_port = data.split('m=')[1].split()[1]
        audio_file = config_dict['audio']['path']
        for_run = './mp32rtp -i 127.0.0.1 -p %s < %s' % (rtp_port, audio_file)
        os.system(for_run)


def bye(my_socket, config_dict, login):
    msg = 'BYE sip:%s SIP/2.0\r\n\r\n' % (login)
    data = connect_to_proxy(msg, my_socket, config_dict)
    if '200 OK' in data:
        write_log(config_dict, 'Finishing...\n\r')

if __name__ == '__main__':
    methods = {'REGISTER': register, 'INVITE': invite, 'BYE': bye}
    config, method, option = take_args()
    config_dict = get_tags(config, ConfigUAHandler)
    log_path = config_dict['log']['path']

    # try:
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    methods[method](my_socket, config_dict, option)
    # except:
    #     sys.exit('Usage: python uaclient.py config method option')
    my_socket.close()
