# -*- coding: utf-8 -*-
import logging

from django.core.management.base import BaseCommand

from seahub.share.constants import STATUS_VETO, STATUS_PASS
from seahub.share.models import (FileShare, FileShareReviserChain,
                                 FileShareVerify, FileShareApprovalStatus)
from seahub.profile.models import DetailedProfile

# Get an instance of a logger
logger = logging.getLogger(__name__)


class Command(BaseCommand):
    label = "share_migrate_verify_result"

    def handle(self, *args, **kwargs):
        # 1. get all share link creator
        users = FileShare.objects.all().values_list('username', flat=True)

        # 2 get all users' reviser chain
        user_reviser_dict = {}
        for username in users:
            d_profile = DetailedProfile.objects.get_detailed_profile_by_user(username)
            if not d_profile:
                logger.error('Error: No detailed profile(department, ... etc) found for user %s' % username)
                continue

            info = FileShareReviserChain.objects.filter(department_name=d_profile.department)
            if len(info) == 0:
                logger.error('Error: No reviser info in share_filesharereviserchain for dept: %s' % d_profile.department)
                continue
            else:
                user_reviser_dict[username] = info[0]

        # 3.
        l = []
        for r in FileShareVerify.objects.all():
            try:
                user = r.share_link.username
                reviser_info = user_reviser_dict.get(user)
            except FileShare.DoesNotExist:
                logger.error('WARN: Skip share_fileshareverify record: %s, share link is deleted' % r.pk)
                continue

            if not reviser_info:
                logger.error('WARN: Skip share_fileshareverify record: %s, no reviser info found for user: %s' % (r.pk, user))
                continue

            logger.info('INFO: Handle share_fileshareverify record, ID: %s, share link: %s, status: (%s, %s,%s,%s,%s,%s)' % (
                r.pk, r.share_link.get_name(),
                r.DLP_status,
                r.line_manager_status, r.department_head_status,
                r.comanager_head_status, r.compliance_owner_status,
                r.compliance_owner2_status))

            dlp = {}
            dlp['share_link'] = r.share_link
            dlp['email'] = 'dlp'
            dlp['status'] = r.DLP_status
            dlp['vtime'] = r.DLP_vtime
            dlp['msg'] = ''
            l.append(dlp)

            line_manager = {}
            if dlp['status'] == STATUS_PASS or dlp['status'] == STATUS_VETO:
                line_manager['share_link'] = r.share_link
                line_manager['email'] = reviser_info.line_manager_email
                line_manager['status'] = r.line_manager_status
                line_manager['vtime'] = r.line_manager_vtime
                line_manager['msg'] = r.line_manager_msg
                l.append(line_manager)

            s = line_manager.get('status')
            department_head = {}
            if s == STATUS_PASS or s == STATUS_VETO:
                department_head['share_link'] = r.share_link
                department_head['email'] = reviser_info.department_head_email
                department_head['status'] = r.department_head_status
                department_head['vtime'] = r.department_head_vtime
                department_head['msg'] = r.department_head_msg
                l.append(department_head)

            s = department_head.get('status')
            comanager_head = {}
            if s == STATUS_PASS or s == STATUS_VETO:
                comanager_head['share_link'] = r.share_link
                comanager_head['email'] = reviser_info.comanager_head_email
                comanager_head['status'] = r.comanager_head_status
                comanager_head['vtime'] = r.comanager_head_vtime
                comanager_head['msg'] = r.comanager_head_msg
                l.append(comanager_head)

            s = comanager_head.get('status')
            compliance_owner = {}
            if s == STATUS_PASS or s == STATUS_VETO:
                compliance_owner['share_link'] = r.share_link
                compliance_owner['email'] = reviser_info.compliance_owner_email
                compliance_owner['status'] = r.compliance_owner_status
                compliance_owner['vtime'] = r.compliance_owner_vtime
                compliance_owner['msg'] = r.compliance_owner_msg
                l.append(compliance_owner)

                if reviser_info.compliance_owner2_email:
                    compliance_owner2 = {}
                    compliance_owner2['share_link'] = r.share_link
                    compliance_owner2['email'] = reviser_info.compliance_owner2_email
                    compliance_owner2['status'] = r.compliance_owner2_status
                    compliance_owner2['vtime'] = r.compliance_owner2_vtime
                    compliance_owner2['msg'] = r.compliance_owner2_msg
                    l.append(compliance_owner2)

        # 4.
        for ele in l:
            if len(FileShareApprovalStatus.objects.filter(
                    share_link=ele['share_link'], email=ele['email'])) > 0:
                continue

            FileShareApprovalStatus.objects.create(
                share_link=ele['share_link'],
                email=ele['email'], status=ele['status'], msg=ele['msg'],
                vtime=ele['vtime'])
            logger.info('INFO: Create new share_fileshareapprovalstatus record, share link %s, email: %s, status: %s' % (
                ele['share_link'].get_name(), ele['email'], ele['status']))
