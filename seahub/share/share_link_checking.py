# -*- coding: utf-8 -*-
"""Utility functions used for share link verify in PingAn Group.
"""

import os
import logging
import json

from django.core.urlresolvers import reverse
from django.http import HttpResponse
from django.utils.translation import ugettext as _

from .models import FileShareVerify, FileShareReviserInfo
from .settings import FUSE_MOUNT_POINT, DLP_SCAN_POINT
from seahub.utils import get_service_url, send_html_email

# Get an instance of a logger
logger = logging.getLogger(__name__)

def check_share_link(request, fileshare, repo):
    """DLP and huamn check share link when create share link.
    """
    username = request.user.username
    content_type = 'application/json; charset=utf-8'

    FileShareVerify(share_link=fileshare).save()

    # Add symbol link for DLP check
    old_cwd = os.getcwd()
    fuse_file = os.path.join(FUSE_MOUNT_POINT, username,
                             repo.id + '_' + repo.name,
                             fileshare.path.lstrip('/')).encode('utf-8') # for lartin system locale

    if os.path.exists(fuse_file):
        symlink = fuse_file.replace(FUSE_MOUNT_POINT, './').rstrip('/')
        try:
            os.chdir(DLP_SCAN_POINT)
            if not os.path.exists(os.path.dirname(symlink)):
                os.makedirs(os.path.dirname(symlink))
            os.symlink(fuse_file, symlink)
            logger.info('Create symbol link %s for %s' % (symlink,
                                                          fuse_file))
        except OSError as e:
            logger.error(e)
    else:
        logger.error('File %s not found in fuse.' % fuse_file)

    os.chdir(old_cwd)  # restore previous current working dir

    data = json.dumps({'token': '', 'download_link': '',
                       'status': str(fileshare.get_status()),
                       'status_str': fileshare.get_status_str() +
                       u'<a href="%s">查看详情。</a>' % reverse('list_shared_links')})
    return HttpResponse(data, status=200, content_type=content_type)

def is_file_link_reviser(username):
    all_revisers = []
    all_reviser_info = FileShareReviserInfo.objects.all()
    for info in all_reviser_info:
        all_revisers.append(info.department_head_email)
        all_revisers.append(info.comanager_head_email)
        all_revisers.append(info.reviser1_email)
        all_revisers.append(info.reviser2_email)

    if username in set(all_revisers):
        return True
    else:
        return False

def email_reviser(fileshare, reviser_email):
    """Send email to revisers to verify shared link.
    """
    subject = _('Please verify new share link.')
    c = {
        'email': fileshare.username,
        'file_name': fileshare.get_name(),
        'file_shared_link': fileshare.get_full_url(),
        'service_url': get_service_url(),
    }
    try:
        send_html_email(subject, 'share/share_link_verify_email.html',
                        c, None, [reviser_email])
        logger.info('Send email to %s, link: %s' % (reviser_email,
                                                    fileshare.get_full_url()))
    except Exception as e:
        logger.error('Faied to send email to %s, please check email settings.' % reviser_email)
        logger.error(e)
