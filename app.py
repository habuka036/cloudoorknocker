#!/usr/bin/env python
# -*- coding:utf-8 -*-

import ConfigParser
import datetime
import logging
import os
import subprocess
import threading
import time


logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(process)d] [%(levelname)s] %(message)s"
)


class Config(object):
    REQUIRE = [
        'api_keys',
        'sec_group',
        'target_ports',
        'revoke_interval',
        'ec2_access_key',
        'ec2_secret_key',
        'ec2_location',
        'persistent_cidrs',
    ]

    LIST_TYPE = [
        'api_keys',
        'target_ports',
        'persistent_cidrs'
    ]

    INT_TYPE = [
        'revoke_interval',
    ]

    def __init__(self):
        filename = os.environ.get('IPAM_CONFIG')
        if filename is None or not os.path.exists(filename):
            raise Exception("IPAM_CONFIG file is required.")
        self.ini = ConfigParser.SafeConfigParser()
        self.ini.read(filename)
        missing = self._check_require()
        if missing:
            raise Exception("requires : %s" % missing)

    def _check_require(self):
        return [c for c in Config.REQUIRE if not self._has(c)]

    def _has(self, key):
        return self.ini.has_option('DEFAULT', key)

    def _get(self, key, default=None):
        value = self.ini.get('DEFAULT', key)
        return value if not value is None else default

    def _get_list(self, key, default=[]):
        values = self._get(key, default)
        return [v.strip() for v in values.split(",")]

    def _get_int(self, key):
        return int(self._get(key))

    def __getattr__(self, name):
        if name in Config.REQUIRE:
            if name in Config.LIST_TYPE:
                return self._get_list(name)
            elif name in Config.INT_TYPE:
                return self._get_int(name)
            else:
                return self._get(name)
        else:
            raise AttributeError


class IPAM(object):
    def __init__(self, limit):
        self.limit = limit
        self.lock = threading.Lock()
        self._target = {}

    def put(self, ruleid):
        self.lock.acquire()
        try:
            self._target[ruleid] = datetime.datetime.now()
            logging.debug("authorize ruleid:%s, time:%s" % (ruleid, self._target[ruleid]))
        finally:
            self.lock.release()

    def pop_expired(self):
        self.lock.acquire()
        try:
            for ruleid, last_access in self._target.items():
                if self._is_expired(last_access):
                    logging.debug("expired : %s" % ruleid)
                    found = ruleid
                    break
            else:
                return None
            # remove rule
            del self._target[found]
            return found
        finally:
            self.lock.release()

    def _is_expired(self, timestamp):
        now = datetime.datetime.now()
        # logging.debug("_is_expired: now = %s, timestamp = %s" % (now, timestamp))
        duration = now - timestamp
        total_seconds = (duration.microseconds + (duration.seconds + duration.days * 24 * 3600) * 10**6) / 10**6
        # logging.debug("total_seconds: %s, limit: %s" % (total_seconds, self.limit))
        if total_seconds > self.limit:
            return True
        return False


class Revoker(threading.Thread):

    def __init__(self, ipam):
        threading.Thread.__init__(self)
        self.ipam = ipam

    def run(self):
        while True:
            try:
                ruleid = self.ipam.pop_expired()
                if ruleid:
                    revoke(ruleid)
            except Exception as e:
                logging.error(e)
            time.sleep(1)


def get_api_key(environ):
    query = environ.get('QUERY_STRING', None)
    if query is not None and 'api_key' in query:
        api_key = query.split('api_key=', 1)
        return api_key[1]
    return None


def authenticate(api_key):
    return api_key in CONF.api_keys


def authorize(remote_ip):
    ruleid = ""
    logging.debug("authorizing: %s" % remote_ip)
    for target_port in CONF.target_ports:
        try:
            cmd = ["/usr/bin/cloudmonkey",
                   "authorizeSecurityGroupIngress",
                   "securitygroupname=%s" % CONF.sec_group,
                   "cidrlist=%s/32" % remote_ip,
                   "startport=%s" % target_port,
                   "endport=%s" % target_port,
                   "protocol=tcp"
                  ]
            p = subprocess.Popen(cmd,
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 shell=False)
            for line in p.stdout.readlines():
                if line.lstrip().startswith('ruleid = '):
                    ruleid = line.split('=', 1)[1].strip()
                    break

        except Exception as e:
            logging.error("Failed to authorize remote_ip: %s port: %s" % (
                            remote_ip, target_port)
                         )
            logging.error(e)

    global ipam
    ipam.put(ruleid)


def revoke(ruleid):
    logging.debug("revoking : %s" % ruleid)
    for target_port in CONF.target_ports:
        try:
            cmd = ["/usr/bin/cloudmonkey",
                   "revokeSecurityGroupIngress",
                   "id=%s" % ruleid]
            p = subprocess.Popen(cmd,
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 shell=False)
        except Exception as e:
            logging.error("Failed to revoke ruleid: %s port: %s" % (
                            ruleid, target_port)
                         )
            logging.error(e)


def render_response(start_response, data, code):
    start_response(code, [
        ("Content-Type", "text/plain"),
        ("Content-Length", str(len(data)))
    ])
    return iter([data])


def persistent_auth():
    #cidrs = CONF.persistent_cidrs
    #logging.debug("persistent cidrs: %s" % cidrs)
    for cidr in CONF.persistent_cidrs:
        logging.debug("persistent authorizing: %s" % cidr)
        for target_port in CONF.target_ports:
            try:
                cmd = ["/usr/bin/cloudmonkey",
                       "authorizeSecurityGroupIngress",
                       "securitygroupname=%s" % CONF.sec_group,
                       "cidrlist=%s" % cidr,
                       "startport=%s" % target_port,
                       "endport=%s" % target_port,
                       "protocol=tcp"
                      ]
                p = subprocess.Popen(cmd,
                                     stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     shell=False)
                for line in p.stdout.readlines():
                    if line.lstrip().startswith('ruleid = '):
                        ruleid = line.split('=', 1)[1].strip()
                        logging.debug("authorized cidr:%s, rule: %s" % (
                                      cidr, ruleid))
                        break

            except Exception as e:
                logging.error("Failed to authorize cidr: %s port: %s" % (
                                cidr, target_port)
                             )
                logging.error(e)


def app(environ, start_response):
    remote_ip = environ.get('REMOTE_ADDR', None)
    logging.debug("remote_ip: %s" % remote_ip)

    api_key = get_api_key(environ)
    logging.debug("api_key: %s" % api_key)

    if not authenticate(api_key):
        logging.warn("Got Unauthorized Request. Danger %s" % remote_ip)
        data = "Unauthorized\n"
        code = "401 Unauthorized"
        return render_response(start_response, data, code)

    authorize(remote_ip)

    data = "Your IP is %s. Accept\n" % remote_ip
    code = "200 OK"
    return render_response(start_response, data, code)


CONF = Config()
persistent_auth()
ipam = IPAM(CONF.revoke_interval)
revoker = Revoker(ipam)
revoker.start()
