#!/usr/bin/python3

import os
import sys
import requests
import urllib3
import json
import time
from configparser import ConfigParser

parser = ConfigParser()
parser.read('conf.d/01-private.conf')

print(parser.get('pve_config', 'PVE_HOST'))

# PVE_HOST = os.getenv('PVE_HOST')
# PVE_PORT = os.getenv('PVE_PORT')
# PVE_USER = os.getenv('PVE_USERNAME')
# PVE_PASS = os.getenv('PVE_PASSWORD')

PVE_HOST = parser.get('pve_config', 'PVE_HOST')
PVE_PORT = parser.get('pve_config', 'PVE_PORT')
PVE_USER = parser.get('pve_config', 'PVE_USER')
PVE_PASS = parser.get('pve_config', 'PVE_PASS')
PVE_CACERT = parser.get('pve_config', 'PVE_CACERT')
USE_VERIFYSSL = bool(parser.get('pve_config', 'USE_VERIFYSSL'))

if USE_VERIFYSSL:
    cacert = PVE_CACERT
else:
    cacert = False

def loadConfig():
    global PVE_HOST
    global PVE_PORT
    global PVE_USER
    global PVE_PASS
    global PVE_CACERT

    DEFAULT_HOST = "https://localhost"
    DEFAULT_PORT = "8006"
    DEFAULT_USER = "root@pam"
    DEFAULT_PASS = "admin"
    DEFAULT_CACERT = "certs/pve-ssl.pem"
    
    if PVE_HOST is None:
        print('PVE_HOST not set, using default: {}'.format(DEFAULT_HOST))
        PVE_HOST = DEFAULT_HOST
    if PVE_PORT is None:
        print('PVE_PORT not set, using default: {}'.format(DEFAULT_PORT))
        PVE_PORT = DEFAULT_PORT
    if PVE_USER is None:
        print('PVE_USER not set, using default: {}'.format(DEFAULT_USER))
        PVE_USER = DEFAULT_USER
    if PVE_PASS is None:
        print('PVE_PASS not set, using default: {}'.format(DEFAULT_PASS))
        PVE_PASS = DEFAULT_PASS
    if PVE_CACERT is None:
        print('PVE_CACERT not set, using default: {}'.format(DEFAULT_CACERT))
        PVE_CACERT = DEFAULT_CACERT

loadConfig()

responCode = 404

endpoint = '/api2/json/access/ticket'
auth_param = {'username': PVE_USER, 'password': PVE_PASS}
url = '{}:{}{}'.format(PVE_HOST, PVE_PORT, endpoint)
print('Trying to authenticate: {} with user [{}]'.format(url, PVE_USER))
try:
    response = requests.get(url, params = auth_param, verify=cacert)
    responCode = response.status_code
    print('test')

except Exception as e:
    print('Exception: {}'.format(e))
else:
    if (responCode == 200):
        print('Authentication SUCCESS')
    elif (responCode == 401):
        print('Authentication Failure for user [{}]'.format(PVE_USER))