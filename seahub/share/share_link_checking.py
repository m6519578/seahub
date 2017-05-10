# -*- coding: utf-8 -*-
"""Utility functions used for share link verify in PingAn Group.
"""

import os
import logging
import string
from collections import namedtuple

from django.utils import translation
from django.utils.translation import ugettext as _

from .settings import (FUSE_MOUNT_POINT, DLP_SCAN_POINT,
                       ENABLE_FILESHARE_DLP_CHECK)
from seahub.profile.models import Profile, DetailedProfile
from seahub.share.constants import STATUS_PASS
from seahub.share.models import (FileShareVerify, FileShareReviserChain,
                                 FileShareReviserMap, FileShareVerifyIgnore)
from seahub.utils import get_service_url, send_html_email

# Get an instance of a logger
logger = logging.getLogger(__name__)

def _symbol_link_file_for_dlp_check(username, repo, fileshare):
    # Add symbol link for DLP check
    old_cwd = os.getcwd()
    fuse_file = os.path.join(FUSE_MOUNT_POINT, username,
                             repo.id + '_' + repo.name,
                             fileshare.path.lstrip('/')).encode('utf-8')  # for lartin system locale

    if os.path.exists(fuse_file):
        symlink = fuse_file.replace(FUSE_MOUNT_POINT, './').rstrip('/')
        try:
            os.chdir(DLP_SCAN_POINT)
            if not os.path.exists(os.path.dirname(symlink)):
                os.makedirs(os.path.dirname(symlink))
            os.symlink(fuse_file, symlink)
            logger.info('Create symbol link %s for %s' % (symlink, fuse_file))
        except OSError as e:
            logger.error(e)
    else:
        logger.error('File %s not found in fuse.' % fuse_file)

    os.chdir(old_cwd)  # restore previous current working dir


def check_share_link(request, fileshare, repo):
    """DLP and huamn check share link when create share link.
    """
    username = request.user.username

    fs_v = FileShareVerify(share_link=fileshare)

    if not ENABLE_FILESHARE_DLP_CHECK:
        # dlp is disabled, pass
        fs_v.DLP_status = STATUS_PASS

    if FileShareVerifyIgnore.objects.filter(username=fileshare.username).exists():
        # this user is ignored for verify, pass
        fs_v.line_manager_status = STATUS_PASS
        fs_v.department_head_status = STATUS_PASS
        fs_v.comanager_head_status = STATUS_PASS
        fs_v.compiance_owner_status = STATUS_PASS

    fs_v.save()

    if ENABLE_FILESHARE_DLP_CHECK:
        _symbol_link_file_for_dlp_check(username, repo, fileshare)

def is_file_link_reviser(username):
    """Check whether a user is a reviser.
    """
    all_revisers = []

    all_reviser_info = FileShareReviserChain.objects.all()  # TODO: performance issue ?
    for info in all_reviser_info:
        all_revisers.append(info.line_manager_email)
        all_revisers.append(info.department_head_email)
        all_revisers.append(info.comanager_head_email)
        all_revisers.append(info.compliance_owner_email)

    all_revisers += FileShareReviserMap.objects.values_list('reviser_email',
                                                            flat=True)

    return True if username in set(map(string.lower, all_revisers)) else False


def email_reviser(fileshare, reviser_email):
    """Send email to revisers to verify shared link.
    If DLP veto, show veto message to revisers.
    """
    subject = _('Please verify new share link.')
    try:
        fs_verify = FileShareVerify.objects.get(share_link=fileshare)
        show_dlp_veto_msg = fs_verify.dlp_veto()
    except FileShareVerify.DoesNotExist:
        show_dlp_veto_msg = False

    c = {
        'email': fileshare.username,
        'file_name': fileshare.get_name(),
        'file_shared_link': fileshare.get_full_url(),
        'service_url': get_service_url(),
        'show_dlp_veto_msg': show_dlp_veto_msg,
    }
    try:
        send_html_email(subject, 'share/share_link_verify_email.html',
                        c, None, [reviser_email])
        logger.info('Send email to %s, link: %s' % (reviser_email,
                                                    fileshare.get_full_url()))
    except Exception as e:
        logger.error('Faied to send email to %s, please check email settings.' % reviser_email)
        logger.error(e)

def email_verify_result(fileshare, email_to, source='DLP', result_code=1):
    """Send email to `email_to` about shared link verify result.
    """
    # save current language
    cur_language = translation.get_language()

    # get and active user language
    user_language = Profile.objects.get_user_language(email_to)
    translation.activate(user_language)

    c = {
        'source': source,
        'result_code': result_code,
        'file_name': fileshare.get_name(),
        'service_url': get_service_url().rstrip('/'),
    }
    subject = _('Verification status of your share link.')
    try:
        send_html_email(subject, 'share/share_link_verify_result_email.html',
                        c, None, [email_to])
        logger.info('Send verify result email to %s, link: %s' % (
            email_to, fileshare.get_full_url()))
    except Exception as e:
        logger.error('Faied to send verify result email to %s' % email_to)
        logger.error(e)

    # restore current language
    translation.activate(cur_language)

def get_reviser_info_by_user(username):
    """Get revisers info(username, account, email) by username.
    First looking to ``FileShareReviserMap``, return result if found, otherwise
    use department relations in ``FileShareReviserChain``.
    """
    r_info = namedtuple('ReviserInfo', [
        'line_manager_name', 'line_manager_account', 'line_manager_email',
        'department_head_name', 'department_head_account', 'department_head_email',
        'comanager_head_name', 'comanager_head_account', 'comanager_head_email',
        'compliance_owner_name', 'compliance_owner_account', 'compliance_owner_email'])

    r_map = FileShareReviserMap.objects.filter(username=username)
    if len(r_map) > 0:
        ret = r_info(
            line_manager_name=r_map[0].reviser_name,
            line_manager_account=r_map[0].reviser_account,
            line_manager_email=r_map[0].reviser_email,
            department_head_name=r_map[0].reviser_name,
            department_head_account=r_map[0].reviser_account,
            department_head_email=r_map[0].reviser_email,
            comanager_head_name=r_map[0].reviser_name,
            comanager_head_account=r_map[0].reviser_account,
            comanager_head_email=r_map[0].reviser_email,
            compliance_owner_name=r_map[0].reviser_name,
            compliance_owner_account=r_map[0].reviser_account,
            compliance_owner_email=r_map[0].reviser_email)
        return ret

    d_profile = DetailedProfile.objects.get_detailed_profile_by_user(username)
    if not d_profile:
        logger.error('No detailed profile(department, ... etc) found for user %s' % username)
        return None

    res = FileShareReviserChain.objects.filter(department_name=d_profile.department)
    if len(res) == 0:
        logger.error('No reviser info found for user: %s' % username)
        return None
    elif len(res) > 1:
        logger.error('Duplicated reviser info found for department: %s' % d_profile.department)
        row = res[0]
    else:
        row = res[0]

    if not row.line_manager_email or \
       not row.department_head_email or \
       not row.comanager_head_email or \
       not row.compliance_owner_email:
        logger.error('Email is empty in chain: %s' % row)

    ret = r_info(
        line_manager_name=row.line_manager_name,
        line_manager_account=row.line_manager_account,
        line_manager_email=row.line_manager_email,
        department_head_name=row.department_head_name,
        department_head_account=row.department_head_account,
        department_head_email=row.department_head_email,
        comanager_head_name=row.comanager_head_name,
        comanager_head_account=row.comanager_head_account,
        comanager_head_email=row.comanager_head_email,
        compliance_owner_name=row.compliance_owner_name,
        compliance_owner_account=row.compliance_owner_account,
        compliance_owner_email=row.compliance_owner_email)

    return ret
