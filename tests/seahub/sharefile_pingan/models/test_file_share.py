import datetime
from django.core import mail

from seahub.share.models import FileShare, FileShareVerify, FileShareExtraInfo
from seahub.share.constants import STATUS_PASS, STATUS_VERIFING
from seahub.test_utils import BaseTestCase


class FileShareTest(BaseTestCase):
    def test_need_notify(self):
        assert len(FileShareVerify.objects.all()) == 0

        fs = FileShare.objects.create_file_link(self.user.username,
                                                self.repo.id, self.file)
        fs_v = FileShareVerify(share_link=fs)
        fs_v.save()

        assert len(FileShare.objects.all()) == 1
        assert len(FileShareVerify.objects.all()) == 1
        assert fs.need_remind() is False

        fs_v.DLP_status = 1
        fs_v.line_manager_status = 1
        fs_v.department_head_status = 1
        fs_v.comanager_head_status = 1
        fs_v.compliance_owner_status = 1
        fs_v.save()
        fs = FileShare.objects.all()[0]
        assert fs.need_remind() is False

        fs_v.DLP_status = 1
        fs_v.line_manager_status = 2
        fs_v.department_head_status = 0
        fs_v.comanager_head_status = 0
        fs_v.compliance_owner_status = 0
        fs_v.save()
        fs = FileShare.objects.all()[0]
        assert fs.need_remind() is False

        fs_v.DLP_status = 1
        fs_v.line_manager_status = 1
        fs_v.department_head_status = 0
        fs_v.comanager_head_status = 0
        fs_v.compliance_owner_status = 0
        fs_v.save()
        fs = FileShare.objects.all()[0]
        assert fs.need_remind() is True

        fs_v.DLP_status = 0
        fs_v.line_manager_status = 1
        fs_v.department_head_status = 0
        fs_v.comanager_head_status = 0
        fs_v.compliance_owner_status = 0
        fs_v.save()
        fs = FileShare.objects.all()[0]
        assert fs.need_remind() is False

    def test_can_email_receivers(self):
        fs = FileShare.objects.create_file_link(self.user.username,
                                                self.repo.id, self.file)
        FileShareExtraInfo.objects.create(share_link=fs, sent_to='1@1.com', note='')
        FileShareExtraInfo.objects.create(share_link=fs, sent_to='2@2.com', note='')

        assert len(mail.outbox) == 0
        fs.email_receivers()
        assert len(mail.outbox) == 2
        assert 'A file is shared to you on' in mail.outbox[0].subject

    def test_get_pass_time(self):
        fs = FileShare.objects.create_file_link(self.user.username,
                                                self.repo.id, self.file)
        fs_v = FileShareVerify(share_link=fs)
        fs_v.DLP_status = STATUS_PASS
        fs_v.line_manager_status = STATUS_PASS
        fs_v.department_head_status = STATUS_PASS
        fs_v.comanager_head_status = STATUS_PASS
        fs_v.compliance_owner_status = STATUS_PASS
        t1 = datetime.datetime.now()
        fs_v.compliance_owner_vtime = t1
        fs_v.save()

        assert fs.pass_verify() is True
        assert fs.get_pass_time() == t1.strftime('%Y-%m-%d %H:%M')

        fs_v.DLP_status = STATUS_PASS
        fs_v.line_manager_status = STATUS_PASS
        fs_v.department_head_status = STATUS_PASS
        fs_v.comanager_head_status = STATUS_PASS
        fs_v.compliance_owner2_status = STATUS_PASS
        t2 = datetime.datetime.now()
        fs_v.compliance_owner2_vtime = t2
        fs_v.save()

        assert fs.pass_verify() is True
        assert fs.get_pass_time() == t2.strftime('%Y-%m-%d %H:%M')

        fs_v.DLP_status = STATUS_VERIFING
        fs_v.line_manager_status = STATUS_VERIFING
        fs_v.department_head_status = STATUS_PASS
        fs_v.comanager_head_status = STATUS_PASS
        fs_v.compliance_owner2_status = STATUS_PASS
        t2 = datetime.datetime.now()
        fs_v.compliance_owner2_vtime = t2
        fs_v.save()

        assert fs.pass_verify() is False
        assert fs.get_pass_time() == ''
