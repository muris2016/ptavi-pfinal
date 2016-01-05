#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import socket
import hashlib
from xml.sax import make_parser
from xml.sax.handler import ContentHandler

class ConfigUAHandler(ContentHandler):
    def __init__ (self):

        self.labels = {'account': {'username': '', 'passwd': ''},
                       'uaserver': {'ip': '', 'puerto': ''},
                       'rtpaudio':  {'puerto': ''},
                       'regproxy': {'ip': '', 'puerto': ''},
                       'log': {'path': ''}, 'audio': {'path': ''}}

        self.conf_ua_dict = {}

    def startElement(self, name, attrs):
        if name in self.labels:
            my_dict = {key: attrs.get(key, '') for key in self.labels[name]}
            self.conf_ua_dict[name] =  my_dict

def get_tags(config, Handler):
    parser = make_parser()
    cHandler = Handler()
    parser.setContentHandler(cHandler)
    parser.parse(open(config))
    return cHandler.conf_ua_dict

def take_args():
    if len(sys.argv) != 4:
        sys.exit("Usage: python uaclient.py config method option")
    else:
        return sys.argv[1], sys.argv[2], sys.argv[3]

def get_hash(nonce, passwd):
    m = hashlib.md5()
    m.update(nonce.encode('utf-8'))
    m.update(passwd.encode('utf-8'))
    return m.hexdigest()


def connect_to_pr(msg, my_socket, conf_ua_dict):
    server = conf_ua_dict['regproxy']['ip']
    port = int(conf_ua_dict['regproxy']['puerto'])
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.connect((server, port))
    my_socket.send(bytes(msg, 'utf-8'))

def register(conf_ua_dict, expires):
    expires = int(expires)
    username = conf_ua_dict['account']['username']
    msg = 'REGISTER sip:%s SIP/2.0\r\nExpires: %s\r\n\r\n' % (username, expires)
    print(msg)
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connect_to_pr(msg, my_socket, conf_ua_dict)

    data = my_socket.recv(1024).decode('utf-8').split()
    print(" ".join(data))
    if 'Unauthorized' in data:
        nonce = data[-1].split('=')[-1]
        passwd = conf_ua_dict['account']['passwd']
        response = get_hash(nonce, passwd)
        msg = 'REGISTER sip:%s SIP/2.0\r\nExpires: %s\r\n' % (username, expires)
        msg += 'Authorization: response=%s\r\n\r\n' % (response)
        print(msg)
        connect_to_pr(msg, my_socket, conf_ua_dict)

def bye():
    print('bye')

if __name__ == "__main__":
    methods = {"REGISTER": register, "BYE": bye}
    config, method, option = take_args()
    conf_ua_dict = get_tags(config, ConfigUAHandler)
    # try:
    methods[method](conf_ua_dict, option)
    # except:
    #     sys.exit("Usage: python uaclient.py config method option")
