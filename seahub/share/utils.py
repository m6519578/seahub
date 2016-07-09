# TODO: merge to `share_link_checking.py` ?
from django.core.cache import cache
from seahub.share.settings import (SHARE_LINK_DECRYPT_ATTEMPT_TIMEOUT,
                                   SHARE_LINK_DECRYPT_ATTEMPT_LIMIT,
                                   ENABLE_SHARE_LINK_VERIFY_CODE)

SHARE_LINK_DECRYPT_ATTEMPT_PREFIX = 'ShareLinkDecryptAttempt_'

def get_share_link_decrypt_failed_attempts(ip):
    return cache.get(SHARE_LINK_DECRYPT_ATTEMPT_PREFIX + ip, 0)

def incr_share_link_decrypt_failed_attempts(ip):
    timeout = SHARE_LINK_DECRYPT_ATTEMPT_TIMEOUT

    try:
        ip_attempts = cache.incr(SHARE_LINK_DECRYPT_ATTEMPT_PREFIX + ip)
        return ip_attempts
    except ValueError:
        cache.set(SHARE_LINK_DECRYPT_ATTEMPT_PREFIX + ip, 1, timeout)
        return 1

def clear_share_link_decrypt_failed_attempts(ip):
    cache.delete(SHARE_LINK_DECRYPT_ATTEMPT_PREFIX + ip)

def show_captcha_share_link_password_form(ip):
    if get_share_link_decrypt_failed_attempts(ip) >= SHARE_LINK_DECRYPT_ATTEMPT_LIMIT:
        return True
    else:
        return False

def get_unusable_verify_code():
    return '__unusable_code__'              # this will never be a valid code

def enable_share_link_verify_code():
    return ENABLE_SHARE_LINK_VERIFY_CODE
