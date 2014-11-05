#!/usr/bin/python
import sys
import logging
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0,"/var/www/maldroid/maldroid/")

from maldroid import app as application
application.secret_key = 'GHJklfdsy82123ty8gsoudgfhou32'
