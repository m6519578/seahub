from django.core.urlresolvers import reverse
from django.core import mail

from seahub.test_utils import BaseTestCase
from seahub.share.models import FileShare
from .mixins import SetupRevisersMixin, AddDownloadLinkMixin


class AJAXChangeDLLinkStatusTest(BaseTestCase, SetupRevisersMixin, AddDownloadLinkMixin):
    def setUp(self):
        self.setup_revisers()
        self.user_repo_id = self.repo.id
        self.user_dir_path = self.folder
        self.user_file_path = self.file
        self.fs = self.add_shared_file_link()

        self.url = reverse('ajax_change_dl_link_status')

    def test_can_veto(self):
        assert len(FileShare.objects.all()) == 1
        self.login_as(self.user)

        resp = self.client.post(self.url, {
            't': self.fs.token,
            's': 2,
        }, HTTP_X_REQUESTED_WITH='XMLHttpRequest')

        self.assertEqual(200, resp.status_code)
        assert FileShare.objects.all()[0].reject_verify() is True

        assert 'reject' in mail.outbox[0].body
        assert '/share/links/' in mail.outbox[0].body

    def test_can_pass(self):
        assert len(FileShare.objects.all()) == 1
        self.login_as(self.user)

        resp = self.client.post(self.url, {
            't': self.fs.token,
            's': 1,
        }, HTTP_X_REQUESTED_WITH='XMLHttpRequest')

        self.assertEqual(200, resp.status_code)
        assert FileShare.objects.all()[0].is_verifing() is True  # still waiting for DLP

        assert 'pass' in mail.outbox[0].body  # approved by user
        assert '/share/links/' in mail.outbox[0].body
