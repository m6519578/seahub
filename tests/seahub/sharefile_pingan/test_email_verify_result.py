from django.core import mail

from seahub.share.share_link_checking import email_verify_result
from seahub.test_utils import BaseTestCase
from .mixins import AddDownloadLinkMixin


class EmailVeiryResultTest(BaseTestCase, AddDownloadLinkMixin):
    def setUp(self):
        self.user_repo_id = self.repo.id
        self.user_dir_path = self.folder
        self.user_file_path = self.file
        
        self.fs = self.add_shared_file_link()

    def test_can_send(self):
        self.assertEqual(len(mail.outbox), 0)

        email_verify_result(self.fs, self.fs.username)

        self.assertEqual(len(mail.outbox), 1)
        assert mail.outbox[0].to[0] == self.fs.username
