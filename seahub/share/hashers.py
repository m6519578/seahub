"""
Default(django.contrib.auth.hashers.PBKDF2PasswordHasher)/AES share link
password hasher, use AES if we remember user's password.
"""
from Crypto.Cipher import AES
import base64

from django.contrib.auth.hashers import make_password as dj_make_password
from django.contrib.auth.hashers import check_password as dj_check_password
from django.conf import settings

from seahub.share.settings import SHARE_LINK_REMEMBER_PASSWORD


class AESPasswordDecodeError(Exception):
    pass

def make_password(password):
    if SHARE_LINK_REMEMBER_PASSWORD:
        return AESPasswordHasher().encode(password)
    else:
        return dj_make_password(password)

def check_password(password, encoded):
    if SHARE_LINK_REMEMBER_PASSWORD:
        try:
            return AESPasswordHasher().verify(password, encoded)
        except AESPasswordDecodeError:
            # For compatibility, we send old password to Django's default
            # hasher to verify.
            return dj_check_password(password, encoded)
    else:
        return dj_check_password(password, encoded)

def decode_password(encoded):
    if not encoded:
        return None

    if SHARE_LINK_REMEMBER_PASSWORD:
        try:
            return AESPasswordHasher().decode(encoded)
        except AESPasswordDecodeError:
            return None
    else:
        return None

# the block size for the cipher object; must be 16, 24, or 32 for AES
BLOCK_SIZE = 32

# the character used for padding--with a block cipher such as AES, the value
# you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
# used to ensure that your value is always a multiple of BLOCK_SIZE
PADDING = '{'

# one-liner to sufficiently pad the text to be encrypted
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

# one-liners to encrypt/encode and decrypt/decode a string
# encrypt with AES, encode with base64
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

class AESPasswordHasher:
    algorithm = 'aes'

    def __init__(self, secret=None):
        if not secret:
            secret = settings.SECRET_KEY[:BLOCK_SIZE]

        self.cipher = AES.new(secret)

    def encode(self, password):
        return "%s$%s" % (self.algorithm, EncodeAES(self.cipher, password))

    def verify(self, password, encoded):
        return self.decode(encoded) == password

    def decode(self, encoded):
        algorithm, data = encoded.split('$', 1)
        if algorithm != self.algorithm:
            raise AESPasswordDecodeError

        return DecodeAES(self.cipher, data)
