#!/usr/bin/python
# -*- coding: utf-8 -*-

import socket
import sys
import os
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
    rtp_dict = {}

    def handle(self):
        self.methods = {"INVITE": self.invite, "ACK": self.ack, "BYE": self.bye}
        ip = self.client_address[0]
        port = self.client_address[1]

        while 1:
            line = self.rfile.read().decode('utf-8')
            if not line:
                break
            method = line.split()[0]
            self.methods[method](line)

    def invite(self, line):
        print("Recivo inivite")
        print(line)
        self.rtp_dict['port'] = line.split('m=')[1].split()[1]
        self.rtp_dict['ip'] = line.split('m=')[1].split()[1]
        username = conf_ua_dict['account']['username']
        rtpaudio_port = conf_ua_dict['rtpaudio']['puerto']
        msg = "SIP/2.0 100 Trying\r\n\r\n"
        msg += "SIP/2.0 180 Ringing\r\n\r\n"
        msg += "SIP/2.0 200 OK\r\n"
        msg += 'Content-Type: application/sdp\r\n\r\n'
        msg += 'v=0\r\no=%s 127.0.0.1\r\ns=mp3p2p\r\nt=0\r\n' % (username)
        msg += 'm=audio %s RTP\r\n\r\n' % (rtpaudio_port)
        self.wfile.write(bytes(msg, 'utf-8'))

    def ack(self, line):
        print("Recivo ACK")
        print(line)
        rtp_port = self.rtp_dict['port']
        rtp_ip = self.rtp_dict['port']
        audio_file = conf_ua_dict['audio']['path']
        for_run = './mp32rtp -i %s -p %s < %s' % (rtp_ip, rtp_port, audio_file)
        os.system(for_run)

    def bye(self, line):
        print("Recivo bye")
        print(line)
        msg = "SIP/2.0 200 OK\r\n\r\n"
        self.wfile.write(bytes(msg, 'utf-8'))
        self.rtp_dict = {}

if __name__ == "__main__":
    port_uas = int(conf_ua_dict['uaserver']['puerto'])
    serv = socketserver.UDPServer(('', port_uas), UASHandler)
    serv.serve_forever()
