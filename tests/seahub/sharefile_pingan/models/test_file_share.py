from seahub.share.models import FileShare, FileShareVerify
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
