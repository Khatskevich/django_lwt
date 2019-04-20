import unittest
from test import support
import json
import time

from .bwt import BWT
from . import exceptions as BEx


class MyTestCase1(unittest.TestCase):

    def setUp(self):
        self.bwt = BWT('secret key asdjasdjasd')

    def test_encode_decode(self):
        app_version = 1
        data = {
                'some data': 'some value',
                }
        msg = json.dumps(data, ensure_ascii=False,
                         separators=(',', ':')).encode('utf-8')
        token = self.bwt.encode(msg, app_version)
        msg_dec = self.bwt.decode(token, time.time() - 10)
        data_dec = json.loads(msg_dec['msg'])
        self.assertDictEqual(data, data_dec)
        self.assertEqual(app_version, msg_dec['app_version'])

    def test_decode_fail(self):
        try:
            self.bwt.decode("bad_token", time.time() - 10)
        except BEx.BWTInvalid:
            self.assertTrue(True)
        else:
            self.assertTrue(False)

        try:
            self.bwt.decode("123.123.12", time.time() - 10)
        except BEx.BWTInvalid:
            self.assertTrue(True)
        else:
            self.assertTrue(False)

    def test_decode_expired(self):
        msg = json.dumps({}, ensure_ascii=False,
                         separators=(',', ':')).encode('utf-8')
        token = self.bwt.encode(msg)
        try:
            self.bwt.decode(token, time.time() + 10)
        except BEx.BWTExpired:
            self.assertTrue(True)
        else:
            self.assertTrue(False)
