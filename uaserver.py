#!/usr/bin/python
# -*- coding: utf-8 -*-
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import uaclient

if __name__ == "__main__":
    
    print(uaclient.get_tags())
