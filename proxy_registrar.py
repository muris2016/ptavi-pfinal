#!/usr/bin/python
# -*- coding: utf-8 -*-

import socketserver
import random
import json
import hashlib
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from uaclient import ConfigUAHandler
from uaclient import get_tags
from uaclient import get_hash


class ConfigPRHandler(ConfigUAHandler):
    def __init__ (self):

        self.labels = {'server': {'name': '', 'ip': '', 'puerto': ''},
                       'database': {'path': '', 'passwdpath': ''},
                       'log': {'path': ''}}

        self.conf_ua_dict = {}

conf_ua_dict = get_tags('pr.xml', ConfigPRHandler)

class SIPPRHandler(socketserver.DatagramRequestHandler):
    def handle(self):
        self.methods = {"REGISTER": self.register, "BYE": self.bye}
        ip = self.client_address[0]
        port = self.client_address[1]
        print (ip, port, "wrote:")
        while 1:
            line = self.rfile.read().decode('utf-8')
            if not line:
                break
            print(line)
            method = line.split()[0]
            # try:
            self.methods[method](line)
            # except:
            #     print("Usage: python uaclient.py config method option")

    def register(self, line):
        login = line.split()[1].split(':')[1]
        passwdpath = conf_ua_dict['database']['passwdpath']
        with open(passwdpath, 'r') as outfile:
            json_str = outfile.read()
            passwd_dict = json.loads(json_str)

        if not 'Authorization: response=' in line:
            nonce = str(random.randrange(10**22))
            passwd_dict[login]['last_nonce'] = nonce
            with open(passwdpath, 'w') as outfile:
                json.dump(passwd_dict, outfile, sort_keys=True, indent=4)

            self.wfile.write(b'SIP/2.0 401 Unauthorized\r\n'
                             + b'WWW Authenticate: nonce='
                             + nonce.encode('utf-8') + b'\r\n\r\n')
        else:
            user_response = line.split('=')[-1]
            nonce = str(passwd_dict[login]['last_nonce'])
            passwd = passwd_dict[login]['passwd']
            response = get_hash(nonce, passwd)
            if user_response == response:
                self.wfile.write(b"SIP/2.0 200 OK\r\n\r\n")
            else:
                self.wfile.write(b"SIP/2.0 400 BAD REQUEST\r\n\r\n")

    def bye():
        pass

def right_nonce():
    return False

if __name__ == "__main__":
    port = int(conf_ua_dict['server']['puerto'])
    serv = socketserver.UDPServer(('', port), SIPPRHandler)
    print("Throwing server UDP of SIP...")
    serv.serve_forever()
