from seahub.share.models import FileShareReviserInfo
from seahub.test_utils import BaseTestCase


class FileShareReviserInfoTest:
    pass

class FileShareReviserInfoManagerTest(BaseTestCase):
    def test_can_add(self):
        assert len(FileShareReviserInfo.objects.all()) == 0
        info = FileShareReviserInfo.objects.add_file_share_reviser(
            'dept_A',
            # department head
            self.user.username, self.user.username, self.user.username,
            # co-manager
            self.admin.username, self.admin.username, self.admin.username,
            # reviser 1
            self.admin.username, self.admin.username, self.admin.username,
            # reviser 2
            self.admin.username, self.admin.username, self.admin.username,
        )
        assert len(FileShareReviserInfo.objects.all()) == 1
        assert info.department_name == 'dept_A'
