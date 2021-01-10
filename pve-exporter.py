#!/usr/bin/python3

import os
import sys
import requests
import urllib3
import json
import time
from configparser import ConfigParser
from distutils.util import strtobool

class ProxmoxApi:
    def __init__(self, configFile = None, host = None, port = None, realm = None, username = None, password = None, verify_ssl = None, cacert = None, endpoint = None, workdir = None, debug = False):
        
        load_default_section = True
        config = ConfigParser()
        self.session = requests.Session()

        if workdir is None:
            self.workdir = os.getcwd()
        else:
            self.workdir = workdir
        
        config_default = dict(
            pve_node = "pve",
            pve_host = "https://localhost",
            pve_port = 8006,
            pve_user = "root",
            pve_pass = "admin",
            pve_realm = "pam",
            pve_cacert = "{}/certs/pve-root-ca.pem".format(self.workdir),
            pve_endpoint = "/api2/json/access/ticket",
            verify_ssl = True)
        
        if configFile is None:
            self.configFile = "{}/config.conf".format(self.workdir)
            if not os.path.isfile(self.configFile):
                print ("Default config ({}) not exist! creating...".format(self.configFile))
                try:
                    with open(self.configFile, 'w') as config_file:
                        config['DEFAULT'] = config_default
                        config['DEFAULT']['pve_cacert'] = './certs/pve-root-ca.pem'
                        config['pve_config'] = config_default
                        config.write(config_file)

                except Exception as ei:
                    print('Exception > {}'.format(ei))
        else:
            if configFile.startswith('/'):
                self.configFile = configFile
            elif configFile.startswith('~/'):
                try:
                    self.configFile = os.getenv('HOME') + configFile
                except Exception as ei:
                    print('Exception > {}'.format(ei))
            else:
                self.configFile = "{}/{}".format(self.workdir, configFile)
            
            if not os.path.isfile(self.configFile):
                print ("Configuration file ({}) not exist! Proccess aborted!".format(self.configFile))
                os.sys.exit(1)
        
        config.read(self.configFile)

        user_config = []
        default_config = []

        for section in config.keys():
            if debug:
                print(config[section])
            if not load_default_section:
                break
            for config_item in config_default.keys():
                if section == 'DEFAULT':
                    if config_item in config[section]:
                        default_config.append((config_item, config[section][config_item]))
                        if debug:
                            print('  - {} = {}'.format(config_item, config[section][config_item]))
                    else:
                        if debug:
                            print("No DEFAULT Config for '{}'".format(config_item))
                            print("Set DEAFULT {} = {}".format(config_item, config_default[config_item]))
                        default_config.append((config_item, config_default[config_item]))
                else:
                    if len(user_config) == 0:
                        config_default = dict(default_config)
                    if config_item in config[section]:
                        user_config.append((config_item, config[section][config_item]))
                        if debug:
                            print('  - {} = {}'.format(config_item, config[section][config_item]))
                    else:
                        if debug:
                            print("No pve_config for '{}'".format(config_item))
                            print("Set {} = {} [DEFAULT]".format(config_item, config_default[config_item]))
                        user_config.append((config_item, config_default[config_item]))
        
        running_config = dict(user_config)

        if verify_ssl is None:
            self.verify_ssl = running_config['verify_ssl']
        else:
            self.verify_ssl = verify_ssl
        
        if self.verify_ssl:
            if cacert is None:
                self.cacert = running_config['pve_cacert']
                if debug:
                    print('Using certificate path from config file, cerificate: {}'.format(self.cacert))
            else:
                self.cacert = cacert
                
            if not os.path.isfile(self.cacert):
                print('VERIFY_SSL = True, but certificate ({}) not exist! Proccess aborted'.format(self.cacert))
                os.sys.exit(1)
        else:
            self.cacert = False


        if host is None:
            self.host = running_config['pve_host']
        else:
            self.host = host

        if port is None:
            self.port = running_config['pve_port']
        else:
            self.port = port

        if realm is None:
            self.realm = running_config['pve_realm']
        else:
            self.realm = realm

        if username is None:
            self.username = running_config['pve_user']
        else:
            self.username = username

        if password is None:
            self.password = running_config['pve_pass']
        else:
            self.password = password

        if endpoint is None:
            self.endpoint = running_config['pve_endpoint']
        else:
            self.endpoint = endpoint
        
        self.user = None
        self.ticket = None
        self.token = None
        self.cookies = None
        # self.session = requests.Session()
    
    def login(self, debug = False):

        url = '{}:{}{}'.format(self.host, self.port, self.endpoint)
        try:
            if debug:
                print('Trying to authenticate: {} with user [{}]'.format(url, self.username))
                
            session_response = self.session.post(url,data={"username": "{}".format(self.username), "realm": "{}".format(self.realm), "password": "{}".format(self.password)},verify=self.cacert)
            json_response = json.loads(session_response.content)["data"]
            responCode = session_response.status_code
            if debug:
                print(json.dumps(json_response, indent=2))

        except Exception as e:
            print('Exception: {}'.format(e))

        else:
            if (responCode == 200):
                if debug:
                    print('Authentication SUCCESS')
                self.user = json_response['username']
                self.token = json_response['CSRFPreventionToken']
                self.ticket = json_response['ticket']
                self.cookies = dict(PVEAuthCookie = self.ticket)

            elif (responCode == 401):
                print('Authentication Failure for user [{}]'.format(self.username))

    def get(self, endpoint = None, params = None, debug = False):
        
        url = '{}:{}{}'.format(self.host, self.port, endpoint)
        if debug:
            print('GET: {} with user [{}]'.format(url, self.username))
        try:
            response = self.session.get(url, cookies = self.cookies, params = params, verify=self.cacert)
            self.data = json.loads(response.content)["data"]
            self.status_code = response.status_code
            self.reason = response.reason
            if debug:
                print('Reason: {}'.format(self.reason))
                print(json.dumps(json.loads(response.content), indent=2))

        except Exception as e:
            print('Exception: {}'.format(e))
            self.data = None
            self.status_code = 500
        if debug:
            print('Response: {}'.format(self.status_code))
        http_response = dict(status_code = self.status_code, data = self.data, reason = self.reason)
        return http_response
    
    def post(self, endpoint = None, headers = None, params = None):
        pass

pve = ProxmoxApi(configFile = 'conf.d/01-private.conf')
pve.login()
endpoint = '/api2/json/nodes/pve'
response = pve.get(endpoint = endpoint, debug = True)

print('Code:', response['status_code'])

if ( response['status_code'] == 200):
    data = response['data']
    print(json.dumps(data, indent=2))
                
elif (response['status_code'] == 401):
    data = response['data']
    print(json.dumps(data, indent=2))
    # if 'error' in json_response.keys():
    #     print(json_response['error']['reason'])
else:
    data = response['data']
    print(json.dumps(data, indent=2))
