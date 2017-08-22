# -*- coding: utf-8 -*-
import logging

from django.core.management.base import BaseCommand

from seahub.share.models import (FileShareReviserChain, ApprovalChain,
                                 approval_chain_list2str)

# Get an instance of a logger
logger = logging.getLogger(__name__)


class Command(BaseCommand):
    label = "share_migrate_approval_chain"

    def handle(self, *args, **kwargs):
        # 1. transfer reviser into to approval chain
        all_info = FileShareReviserChain.objects.all()

        l = []
        for info in all_info:
            if info.compliance_owner2_email:
                l.append(
                    (info.department_name,
                     [info.line_manager_email, info.department_head_email,
                      info.comanager_head_email,
                      ('op_or', info.compliance_owner_email, info.compliance_owner2_email)]))

            else:
                l.append(
                    (info.department_name,
                     [info.line_manager_email, info.department_head_email,
                      info.comanager_head_email, info.compliance_owner_email]))

        # 2. import to approval chain
        for ele in l:
            if len(ApprovalChain.objects.filter(department=ele[0])) > 0:
                continue

            ApprovalChain.objects.create_chain(ele[0], ele[1])
            logger.info('Import %s' % ele[0])

        # 3. verify
        print ''
        print 'Done. '
        print ''

        logger.info('List approval chain in share_approvalchain table...')
        qs = ApprovalChain.objects.values_list('department',
                                               flat=True).distinct()
        for dept in qs:
            chain = ApprovalChain.objects.get_by_department(dept)
            chain_str = approval_chain_list2str(chain)
            logger.info('%s <-> %s' % (dept, chain_str))

        print ''
        print 'Total %s chains.' % len(qs)
