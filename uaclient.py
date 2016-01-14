#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
import os
import socket
import hashlib
import threading
import time
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from uaserver import ConfigHandler
from uaserver import get_tags
from uaserver import write_log
# from uaserver import run_cvlc
# from uaserver import send_rtp


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


def run_cvlc(rtpaudio_port):
    for_run = 'cvlc rtp://@127.0.0.1:%s 2> /dev/null &' % (rtpaudio_port)
    print('Receiving audio via rtp')
    os.system(for_run)


def send_rtp(rtp_port, audio_file):
    for_run = './mp32rtp -i 127.0.0.1 -p %s < %s' % (rtp_port, audio_file)
    print('Sending audio via rtp')
    os.system(for_run)
    print('Sending audio has finished')


def connect_to_proxy(msg, my_socket, ack=False):
    ip_server = config_dict['regproxy']['ip']
    port = int(config_dict['regproxy']['puerto'])

    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.connect((ip_server, port))
    my_socket.send(bytes(msg, 'utf-8'))

    write_log(config_dict, 'Sent to', ip_server, port, msg)
    if not ack:
        data = my_socket.recv(1024).decode('utf-8')
        write_log(config_dict, 'Received from', ip_server, port, data)
        for response in response_codes:
            if response in data:
                print(response, 'received')
        return data


def register(my_socket, expires):
    write_log(config_dict, 'Starting...')
    username = config_dict['account']['username']
    port_uas = config_dict['uaserver']['puerto']
    msg = 'REGISTER sip:%s:%s SIP/2.0\r\n' % (username, port_uas)
    msg += 'Expires: %s\r\n\r\n' % (expires)
    data = connect_to_proxy(msg, my_socket)

    if 'Unauthorized' in data.split():
        nonce = data.split()[-1].split('=')[-1].strip('"')
        passwd = config_dict['account']['passwd']
        response = get_hash(nonce, passwd)
        resp = '\r\nAuthorization: Digest response="%s"\r\n' % (response)
        msg = msg.replace('\r\n', resp, 1)
        connect_to_proxy(msg, my_socket)


def invite(my_socket, login):
    username = config_dict['account']['username']
    rtpaudio_port = config_dict['rtpaudio']['puerto']
    msg = 'INVITE sip:%s SIP/2.0\r\n' % (login)
    msg += 'Content-Type: application/sdp\r\n\r\n'
    msg += 'v=0\r\no=%s 127.0.0.1\r\ns=mp3p2p\r\nt=0\r\n' % (username)
    msg += 'm=audio %s RTP\r\n\r\n' % (rtpaudio_port)
    data = connect_to_proxy(msg, my_socket)

    if '100 Trying' in data and '180 Ring' and data and '200 OK' in data:
        msg = 'ACK sip:%s SIP/2.0\r\n\r\n' % (login)
        connect_to_proxy(msg, my_socket, ack=True)

        rtpaudio_port = config_dict['rtpaudio']['puerto']
        rtp_port = data.split('m=')[1].split()[1]
        audio_file = config_dict['audio']['path']

        t1 = threading.Thread(target=run_cvlc, args=(rtpaudio_port,))
        t2 = threading.Thread(target=send_rtp, args=(rtp_port, audio_file,))
        t1.start()
        time.sleep(0.2)
        t2.start()


def bye(my_socket, login):
    msg = 'BYE sip:%s SIP/2.0\r\n\r\n' % (login)
    data = connect_to_proxy(msg, my_socket)
    if '200 OK' in data:
        os.system('killall mp32rtp 2> /dev/null')
        write_log(config_dict, 'Finishing...\n\r')


def main():
    global response_codes
    response_codes = ['Bad Request', 'User Not Found', 'Method Not Allowed']
    response_codes += ['Address Incomplete', 'Unauthorized', 'OK', 'Decline']
    response_codes += ['Temporarily Unavailable', 'Forbidden', 'Conflict']
    config, method, option = take_args()
    global config_dict
    config_dict = get_tags(config, ConfigHandler)

    return method, option

if __name__ == '__main__':
    methods = {'REGISTER': register, 'INVITE': invite, 'BYE': bye}
    method, option = main()
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        methods[method](my_socket, option)

    except KeyError:
        print('Usage: python uaclient.py config method option')

    except ConnectionRefusedError:
        ip_server = config_dict['regproxy']['ip']
        port = config_dict['regproxy']['puerto']
        error = 'Error: No server listening at %s port %s' % (ip_server, port)
        write_log(config_dict, error)

    my_socket.close()
