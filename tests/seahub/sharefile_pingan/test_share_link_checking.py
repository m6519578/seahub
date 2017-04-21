from seahub.share.models import (FileShareReviserChain, FileShareReviserMap)
from seahub.share.share_link_checking import (
    is_file_link_reviser, get_reviser_info_by_user)
from seahub.test_utils import BaseTestCase

from .mixins import SetupRevisersMixin


class GetReviserInfoByUserTest(BaseTestCase, SetupRevisersMixin):
    def setUp(self):
        self.setup_revisers()

    def test_get_reviser_info_by_user(self):
        info = get_reviser_info_by_user(self.user.username)
        assert info.department_head_email == self.user.username
        assert info.line_manager_email == self.user.username
        assert info.comanager_head_email == self.admin.username
        assert info.compliance_owner_email == self.admin.username

        self.setup_reviser_map()

        info = get_reviser_info_by_user(self.user.username)
        assert info.department_head_email == self.user.username
        assert info.line_manager_email == self.user.username
        assert info.comanager_head_email == self.user.username
        assert info.compliance_owner_email == self.user.username


class IsFileLinkReviserTest(BaseTestCase):
    def test_is_file_link_reviser(self):
        assert is_file_link_reviser(self.user.username) is False
        assert is_file_link_reviser(self.admin.username) is False

        FileShareReviserChain.objects.add_file_share_reviser(
            'dept_A',
            # line manager
            self.user.username, self.user.username, self.user.username,
            # department head
            self.user.username, self.user.username, self.user.username,
            # co-manager
            self.admin.username, self.admin.username, self.admin.username,
            # comliance owner
            self.admin.username, self.admin.username, self.admin.username,
        )

        assert is_file_link_reviser(self.user.username) is True
        assert is_file_link_reviser(self.admin.username) is True

    def test_is_file_link_reviser2(self):
        assert is_file_link_reviser(self.user.username) is False

        FileShareReviserMap.objects.create(
            username=self.user.username, reviser_name='', reviser_account='',
            reviser_email=self.user.username)

        assert is_file_link_reviser(self.user.username) is True

    def test_uppercase_email(self):
        assert is_file_link_reviser(self.user.username) is False

        FileShareReviserMap.objects.create(
            username=self.user.username, reviser_name='', reviser_account='',
            reviser_email=self.user.username.upper())

        assert is_file_link_reviser(self.user.username) is True
