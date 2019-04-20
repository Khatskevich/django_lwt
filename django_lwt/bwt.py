import hmac
import hashlib
import struct
import time
import base64
from . import exceptions as BEx

# Taken from python jwt
def base64url_decode(input):
    rem = len(input) % 4
    if rem > 0:
        input += b'=' * (4 - rem)
    return base64.urlsafe_b64decode(input)


# Taken from python jwt
def base64url_encode(input):
    return base64.urlsafe_b64encode(input).replace(b'=', b'')


class BWT():
    version = 0
    alg = hashlib.sha256

    def __init__(self, key):
        super().__init__()
        if len(key) < 16:
            raise BEx.BWTInvalid('len(key) should be >= 16')
        self.key = key.encode('utf-8')

    def sign(self, msg):
        return hmac.new(self.key, msg, self.alg).digest()

    def verify(self, msg, sig):
        return hmac.compare_digest(sig, self.sign(msg))

    def header_encode(self, app_version, issue_time):
        return struct.pack('!BBL', self.version, app_version, issue_time)

    def header_decode(self, header):
        unpacked = struct.unpack('!BBL', header)
        if unpacked[0] != self.version:
            BEx.BWTNotSupported("Only 0 BWT version is supported")
        return unpacked

    def encode(self, msg, app_version=0):
        issue_time = int(time.time())
        header = base64url_encode(self.header_encode(app_version,
                                                     issue_time))
        msg = base64url_encode(msg)
        if type(msg) != bytes:
            raise BEx.BWTInvalid('Message should be of bytes type')
        segments = [header, msg]
        signature = base64url_encode(self.sign(b'.'.join(segments)))
        segments.append(signature)
        return (b'.'.join(segments)).decode('utf-8')

    def decode(self, data, issue_max_time):
        if type(data) == str:
            data = data.encode('utf-8')
        xsegments = data.split(b'.')
        if len(xsegments) != 3:
            raise BEx.BWTInvalid('Invalid token')
        segments = [base64url_decode(x) for x in xsegments]
        header, msg, signature = segments[0], segments[1], segments[2]
        valid = self.verify(b'.'.join([xsegments[0], xsegments[1]]), signature)
        if not valid:
            raise BEx.BWTInvalid('Invalid token')
        bwt_v, app_version, issue_time = self.header_decode(header)
        ts = time.time()
        if issue_max_time > issue_time:
            raise BEx.BWTExpired()
        res = {
                'msg': msg,
                'issue_time': issue_time,
                'bwt_version': bwt_v,
                'app_version': app_version,
                }
        return res
