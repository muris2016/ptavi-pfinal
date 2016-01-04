#!/usr/bin/python
# -*- coding: utf-8 -*-
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from uaclient import ConfigUAHandler

class ConfigPRHandler(ConfigUAHandler):
    def __init__ (self):
        
        self.labels = {'server': {'name': '', 'ip': ''},
                       'database': {'path': '', 'passwdpath': ''},
                       'log': {'path': ''}}

        self.list_labels = {}


if __name__ == "__main__":
    parser = make_parser()
    cHandler = ConfigPRHandler()
    parser.setContentHandler(cHandler)
    parser.parse(open('pr.xml'))
    print(cHandler.list_labels)
