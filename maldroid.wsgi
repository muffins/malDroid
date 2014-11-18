#!/usr/bin/python
import sys
import logging
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0,"/var/www/maldroid/maldroid/")

import maldroid
application = maldroid.app
application.secret_key = ''
maldroid.init_app()
