from seahub.share.models import FileShare, FileShareVerify
from seahub.test_utils import BaseTestCase


class FileShareTest(BaseTestCase):
    def test_need_notify(self):
        assert len(FileShareVerify.objects.all()) == 0

        fs = FileShare.objects.create_file_link(self.user.username,
                                                self.repo.id, self.file)
        fs_v = FileShareVerify(share_link=fs)
        fs_v.save()

        assert len(FileShareVerify.objects.all()) == 1

        assert fs.need_remind() is True

        fs_v.department_head_status = 1
        fs_v.reviser_status = 1
        fs_v.save()
        assert fs.need_remind() is False
