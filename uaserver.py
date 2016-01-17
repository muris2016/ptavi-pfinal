#!/usr/bin/python
# -*- coding: utf-8 -*-
import time
import socket
import sys
import os
import socketserver
from threading import Thread
from xml.sax import make_parser
from xml.sax.handler import ContentHandler


class ConfigHandler(ContentHandler):
    def __init__(self, proxy):
        if proxy:
            self.labels = {'server': {'name': '', 'ip': '', 'puerto': ''},
                           'database': {'path': '', 'passwdpath': ''},
                           'log': {'path': ''}}
        else:
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


def run_cvlc(config_dict):
    port2rcv = config_dict['rtpaudio']['puerto']
    ip2rcv = config_dict['uaserver']['ip']
    print('Receiving audio via rtp at port %s' % (port2rcv))
    os.system('cvlc rtp://%s:%s 2> /dev/null &' % (ip2rcv, port2rcv))


def send_rtp(rtp_ip, rtp_port, audio_file):
    print('Sending audio via rtp to %s:%s' % (rtp_ip, rtp_port))
    os.system('./mp32rtp -i %s -p %s < %s' % (rtp_ip, rtp_port, audio_file))
    print('Sending audio has finished')


def get_tags(config, Handler, proxy=False):
    parser = make_parser()
    cHandler = Handler(proxy)
    parser.setContentHandler(cHandler)
    parser.parse(open(config))
    return cHandler.config_dict


def write_log(config_dict, event, ip='', port='', msg=''):
    log_path = config_dict['log']['path']
    msg = ' '.join(msg.split())
    with open(log_path, 'a') as outfile:
        hour = time.strftime('%Y%m%d%H%M%S', time.gmtime())
        if ip != '' and msg != '':
            outfile.write('%s %s %s:%s: %s\n' % (hour, event, ip, port, msg))
        elif ip == '':
            outfile.write('%s %s\n' % (hour, event))


class UASHandler(socketserver.DatagramRequestHandler):
    rtp_dict = {}
    threads = {'t1': Thread(), 't2': Thread()}

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
            print(method, 'received')
            self.methods[method](line, ip, port)

    def invite(self, line, ip, port):
        if not self.threads['t2'].isAlive():
            self.rtp_dict['port'] = line.split('m=')[1].split()[1]
            self.rtp_dict['ip'] = line.split('o=')[1].split()[1]
            username = config_dict['account']['username']
            ip = config_dict['uaserver']['ip']
            rtpaudio_port = config_dict['rtpaudio']['puerto']
            msg = 'SIP/2.0 100 Trying\r\n\r\n'
            msg += 'SIP/2.0 180 Ringing\r\n\r\n'
            msg += 'SIP/2.0 200 OK\r\n'
            msg += 'Content-Type: application/sdp\r\n\r\n'
            msg += 'v=0\r\no=%s %s\r\ns=mp3p2p\r\nt=0\r\n' % (username, ip)
            msg += 'm=audio %s RTP\r\n\r\n' % (rtpaudio_port)
            os.system('killall vlc 2> /dev/null')
        else:
            msg = 'SIP/2.0 480 Temporarily Unavailable\r\n\r\n'

        self.wfile.write(bytes(msg, 'utf-8'))
        write_log(config_dict, 'Sent to', ip, port, msg)

    def ack(self, line, ip, port):
        ip = self.rtp_dict['ip']
        port = self.rtp_dict['port']
        audio_f = config_dict['audio']['path']
        self.threads['t1'] = Thread(target=run_cvlc, args=(config_dict,))
        self.threads['t2'] = Thread(target=send_rtp, args=(ip, port, audio_f,))
        self.threads['t1'].start()
        time.sleep(0.2)
        self.threads['t2'].start()

    def bye(self, line, ip, port):
        msg = 'SIP/2.0 200 OK\r\n\r\n'
        self.wfile.write(bytes(msg, 'utf-8'))
        if self.threads['t1'].isAlive():
            os.system('killall mp32rtp 2> /dev/null')
            os.system('killall vlc 2> /dev/null')
        write_log(config_dict, 'Sent to', ip, port, msg)
        self.rtp_dict = {}


def main():
    if len(sys.argv) != 2:
        sys.exit('Usage: python uaserver.py config')
    else:
        config = sys.argv[1]
    global config_dict
    config_dict = get_tags(config, ConfigHandler)
    port_uas = int(config_dict['uaserver']['puerto'])
    return port_uas

if __name__ == '__main__':
    port_uas = main()
    serv = socketserver.UDPServer(('', port_uas), UASHandler)
    print('Listening...')
    serv.serve_forever()
