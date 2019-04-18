import unittest
from test import support
import json
import time

from .bwt import BWT


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
        # import pdb; pdb.set_trace()
        msg_dec = self.bwt.decode(token, time.time() + 10)
        data_dec = json.loads(msg_dec['msg'])
        self.assertDictEqual(data, data_dec)
