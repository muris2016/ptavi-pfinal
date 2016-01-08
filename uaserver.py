#!/usr/bin/python
# -*- coding: utf-8 -*-

import socket
import sys
import os
import socketserver
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from uaclient import ConfigUAHandler
from uaclient import get_tags
from uaclient import write_log


def take_args():
    if len(sys.argv) != 2:
        sys.exit('Usage: python uaserver.py config')
    else:
        return sys.argv[1]

config = take_args()
config_dict = get_tags(config, ConfigUAHandler)


class UASHandler(socketserver.DatagramRequestHandler):
    rtp_dict = {}

    def handle(self):
        self.methods = {'INVITE': self.invite, 'ACK': self.ack}
        self.methods['BYE'] = self.bye
        while 1:
            line = self.rfile.read().decode('utf-8')
            if not line:
                break
            ip = self.client_address[0]
            port = self.client_address[1]
            write_log(config_dict, 'Received from', ip, port, line)
            method = line.split()[0]
            self.methods[method](line, ip, port)

    def invite(self, line, ip, port):
        self.rtp_dict['port'] = line.split('m=')[1].split()[1]
        username = config_dict['account']['username']
        rtpaudio_port = config_dict['rtpaudio']['puerto']
        msg = 'SIP/2.0 100 Trying\r\n\r\n'
        msg += 'SIP/2.0 180 Ringing\r\n\r\n'
        msg += 'SIP/2.0 200 OK\r\n'
        msg += 'Content-Type: application/sdp\r\n\r\n'
        msg += 'v=0\r\no=%s 127.0.0.1\r\ns=mp3p2p\r\nt=0\r\n' % (username)
        msg += 'm=audio %s RTP\r\n\r\n' % (rtpaudio_port)
        self.wfile.write(bytes(msg, 'utf-8'))
        write_log(config_dict, 'Sent to', ip, port, msg)

    def ack(self, line, ip, port):
        rtp_port = self.rtp_dict['port']
        audio_file = config_dict['audio']['path']
        for_run = './mp32rtp -i 127.0.0.1 -p %s < %s' % (rtp_port, audio_file)
        os.system(for_run)

    def bye(self, line, ip, port):
        msg = 'SIP/2.0 200 OK\r\n\r\n'
        self.wfile.write(bytes(msg, 'utf-8'))
        write_log(config_dict, 'Sent to', ip, port, msg)
        self.rtp_dict = {}

if __name__ == '__main__':
    port_uas = int(config_dict['uaserver']['puerto'])
    serv = socketserver.UDPServer(('', port_uas), UASHandler)
    print('Listening...')
    serv.serve_forever()
