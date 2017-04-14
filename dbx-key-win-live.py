#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Original code by Nicolas RUFF
# https://github.com/newsoft/dbx-keygen-windows
#
# Modified by Francesco "dfirfpi" Picasso <francesco.picasso@gmail.com>
# to handle both "KS" and "KS1" registry keys, plus Python3 support, PEP8

from __future__ import print_function

import binascii
import hmac
import struct

try:
    import _winreg
except ImportError:
    import winreg as _winreg

# requires pip install pbkdf2
from pbkdf2 import PBKDF2

# requires pip install pypiwin32
import win32crypt

# ------------------------------------------------------------------------------
# ORIGINALLY FOUND IN pynt/helpers/crypt.py
# REIMPLEMENTED USING:
#  http://sourceforge.net/projects/pywin32/files/pywin32/Build%20217/


def unprotect_data(data_in, extra_entropy=None):
    (desc, data_out) = win32crypt.CryptUnprotectData(
        data_in, extra_entropy, None, None, 0x01)
    return data_out

# ------------------------------------------------------------------------------
# FROM common_util/keystore/keystore_win32.py


class KeyStore(object):

    # KEY LOCATION:
    # (Windows) HKCU\Software\Dropbox\ks\Client REG_BINARY
    # (Linux) 'hostkeys' file (obfuscated)

    def __init__(self, registry_key_name):
        self.registry_key_path = "SOFTWARE\\Dropbox\\" + registry_key_name

    def get_versioned_key(self, name, hmac_keys):

        hkey = _winreg.OpenKey(
            _winreg.HKEY_CURRENT_USER, self.registry_key_path)

        # returns (data, type)
        hmaced_payload = _winreg.QueryValueEx(hkey, name)[0]

        # remove f***ing NULL byte
        # (_winreg.QueryValueEx != Dropbox registry API ?!?)
        hmaced_payload = hmaced_payload[:-1]

        version, payload_len = struct.unpack_from('BL', hmaced_payload)
        hmac_size = len(hmaced_payload) - payload_len - 8
        v, l, payload, h = struct.unpack(
            'BL%ds%ds' % (payload_len, hmac_size), hmaced_payload)

        try:
            hm_key = hmac_keys[v]
        except KeyError:
            raise KeychainMissingItem('Parsing error, bad version')

        hm = hmac.new(hm_key)
        if hm.digest_size != len(h):
            raise KeychainMissingItem('Bad digest size')

        hm.update(hmaced_payload[:-hm.digest_size])
        if hm.digest() != h:
            raise KeychainMissingItem('Bad digest')

        unprotected_payload = unprotect_data(payload, hm_key)

        return (v, unprotected_payload)

# ------------------------------------------------------------------------------
# FROM core/mapreduce.py


class Version0(object):
    USER_HMAC_KEY = b'\xd1\x14\xa5R\x12e_t\xbdw.7\xe6J\xee\x9b'
    APP_KEY = b'\rc\x8c\t.\x8b\x82\xfcE(\x83\xf9_5[\x8e'
    APP_IV = b'\xd8\x9bC\x1f\xb6\x1d\xde\x1a\xfd\xa4\xb7\xf9\xf4\xb8\r\x05'
    APP_ITER = 1066
    USER_KEYLEN = 16
    DB_KEYLEN = 16

    print("APP key: {0}".format(binascii.hexlify(APP_KEY)))

    def get_database_key(self, user_key):
        return PBKDF2(
            passphrase=user_key,
            salt=self.APP_KEY,
            iterations=self.APP_ITER).read(self.DB_KEYLEN)

# ------------------------------------------------------------------------------
# FROM core/mapreduce.py


class DBKeyStore(object):

    def __init__(self, registry_key_name):
        self.parsers = {0: Version0()}
        self.hmac_keys = dict(((
            v, self.parsers[v].USER_HMAC_KEY) for v in self.parsers))
        self.ks = KeyStore(registry_key_name)
        self.max_version = 0
        # simplified version
        # ...
        return

    def get_user_key(self):
        version, user_key = self.ks.get_versioned_key('Client', self.hmac_keys)
        # WARNING: original source displays dropbox_hash(user_key) instead
        # dropbox_hash() is defined in client_api/hashing.py
        print('KEYSTORE: got user key ({0}, {1})'.format(
            version, repr(user_key)))
        return (version, user_key)

    def KeychainAuthCanceled(self, version=0):
        if version:
            raise Exception('invalid version number')
        version, user_key = self.get_user_key()
        return self.parsers[version].get_database_key(user_key)

# ------------------------------------------------------------------------------
# main

dbks = DBKeyStore('ks')
# user_key is a tuple: (version,data)
user_key = dbks.get_user_key()
print("[KS]  User key: {0}".format(binascii.hexlify(user_key[1])))

v0 = Version0()
db_key = v0.get_database_key(user_key[1])
print("[KS]   DBX key: {0}".format(binascii.hexlify(db_key)))

dbks1 = DBKeyStore('ks1')
# user_key is a tuple: (version,data)
user_key = dbks1.get_user_key()
print("[KS1] User key: {0}".format(binascii.hexlify(user_key[1])))

db_key = v0.get_database_key(user_key[1])
print("[KS1]  DBX key: {0}".format(binascii.hexlify(db_key)))
