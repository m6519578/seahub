from seahub.share.models import FileShareReviserChain
from seahub.test_utils import BaseTestCase


class FileShareReviserChainTest:
    pass

class FileShareReviserChainManagerTest(BaseTestCase):
    def test_can_add(self):
        assert len(FileShareReviserChain.objects.all()) == 0
        info = FileShareReviserChain.objects.add_file_share_reviser(
            'dept_A',
            # line manager
            self.user.username, self.user.username, self.user.username,
            # department head
            self.user.username, self.user.username, self.user.username,
            # co-manager
            self.admin.username, self.admin.username, self.admin.username,
            # compliance owner
            self.admin.username, self.admin.username, self.admin.username,
        )
        assert len(FileShareReviserChain.objects.all()) == 1
        assert info.department_name == 'dept_A'
