#!/usr/bin/python
# -*- coding: utf-8 -*-
from xml.sax import make_parser
from xml.sax.handler import ContentHandler

class ConfigUAHandler(ContentHandler):
    def __init__ (self):

        self.labels = {'accout': {'username': '', 'passwd': ''},
                       'uaserver': {'ip': '', 'puerto': ''},
                       'rtpaudio':  {'puerto': ''},
                       'regproxy': {'ip': '', 'puerto': ''},
                       'log': {'path': ''}, 'audio': {'path': ''}}

        self.list_labels = {}

    def startElement(self, name, attrs):
        if name in self.labels:
            my_dict = {key: attrs.get(key, '') for key in self.labels[name]}
            self.list_labels[name] =  my_dict

def get_tags(config):
    parser = make_parser()
    cHandler = ConfigUAHandler()
    parser.setContentHandler(cHandler)
    parser.parse(open(config))
    return cHandler.list_labels


if __name__ == "__main__":
    config = 'ua1.xml'
    print(get_tags(config))
