from django.conf import settings

######################### Start PingAn Group related ########################
ENABLE_FILESHARE_CHECK = getattr(settings, 'ENABLE_FILESHARE_CHECK', False)
FUSE_MOUNT_POINT = getattr(settings, 'FUSE_MOUNT_POINT', '/tmp/seafile_fuse')
DLP_SCAN_POINT = getattr(settings, 'DLP_SCAN_POINT', '/tmp/dlp_scan')
SHARE_LINK_BACKUP_LIBRARY = getattr(settings, 'SHARE_LINK_BACKUP_LIBRARY', None)

SHARE_LINK_REMEMBER_PASSWORD = getattr(settings, 'SHARE_LINK_REMEMBER_PASSWORD', True)
SHARE_LINK_DECRYPT_ATTEMPT_LIMIT = getattr(settings, 'SHARE_LINK_ATTEMPT_LIMIT', 3)
SHARE_LINK_DECRYPT_ATTEMPT_TIMEOUT = getattr(settings, 'SHARE_LINK_DECRYPT_ATTEMPT_TIMEOUT', 15 * 60)
ENABLE_SHARE_LINK_VERIFY_CODE = getattr(settings, 'ENABLE_SHARE_LINK_VERIFY_CODE', True)
######################### End PingAn Group related ##########################
