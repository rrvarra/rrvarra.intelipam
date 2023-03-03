import sys
from datetime import datetime
import logging
import random
import string

from flask import Flask

from . import secrets
sys.path.append("..")
import logutil
from IntelIPAM import IntelIPAM
from autoproxy import AutoProxy

logutil.set_logging(log_file=r'D:\LOGS\IntelIPAM\INTELIPAM_WEBAPP.log')

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.SECRET_KEY

ipam = None
start_ts = datetime.now().isoformat().split('.')[0]
logging.info("Loading IPAM")
try:
    ipam = IntelIPAM()
except Exception as ex:
    logging.error("Failed init IPAM Module: {}".format(ex))


autoproxy_instance = None
logging.info("Loading AutoProxy")
try:
    autoproxy_instance = AutoProxy()
except Exception as ex:
    logging.error("Failed init AutoProxy: {}".format(ex))

logging.info("Init done")

from . import views