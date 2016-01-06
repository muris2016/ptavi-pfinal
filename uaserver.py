#!/usr/bin/python
# -*- coding: utf-8 -*-

import socket
import sys
import socketserver
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import uaclient


def take_args():
    if len(sys.argv) != 2:
        sys.exit("Usage: python uaserver.py config")
    else:
        return sys.argv[1]

config = take_args()
conf_ua_dict = uaclient.get_tags(config, uaclient.ConfigUAHandler)
log_path = conf_ua_dict['log']['path']


class UASHandler(socketserver.DatagramRequestHandler):
    def handle(self):
        self.methods = {"INVITE": self.invite}
        ip = self.client_address[0]
        port = self.client_address[1]
        print (ip, port, "wrote:")
        while 1:
            line = self.rfile.read().decode('utf-8')
            if not line:
                break
            print(line)
            method = line.split()[0]
            self.methods[method](line)

    def invite(self, line):
        ip_server = conf_ua_dict['regproxy']['ip']
        port = int(conf_ua_dict['regproxy']['puerto'])
        username = line.split('o=')[1].split()[0]
        rtpaudio_port = conf_ua_dict['rtpaudio']['puerto']
        msg = "SIP/2.0 100 Trying\r\n\r\n"
        msg += "SIP/2.0 180 Ring\r\n\r\n"
        msg += "SIP/2.0 200 OK\r\n"
        msg += 'Content-Type: application/sdp\r\n\r\n'
        msg += 'v=0\r\no=%s 127.0.0.1\r\ns=mp3p2p\r\nt=0\r\n' % (username)
        msg += 'm=audio %s RTP\r\n\r\n' % (rtpaudio_port)

        my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        my_socket.connect((ip_server, port))
        my_socket.send(bytes(msg, 'utf-8'))
        # uaclient.connect_to_proxy(msg, my_socket, conf_ua_dict
        # self.wfile.write(b"SIP/2.0 100 Trying\r\n\r\n")
        # self.wfile.write(b"SIP/2.0 180 Ring\r\n\r\n")
        # self.wfile.write(b"SIP/2.0 200 OK\r\n\r\n")

if __name__ == "__main__":

    port_uas = int(conf_ua_dict['uaserver']['puerto'])
    serv = socketserver.UDPServer(('', port_uas), UASHandler)
    serv.serve_forever()
