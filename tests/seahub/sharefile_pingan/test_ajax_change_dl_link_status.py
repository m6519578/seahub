from django.core.urlresolvers import reverse
from django.core import mail

from seahub.test_utils import BaseTestCase
from seahub.share.models import FileShare, FileShareVerify
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
            'msg': 'xxx',
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
            'msg': 'xxx',
        }, HTTP_X_REQUESTED_WITH='XMLHttpRequest')

        self.assertEqual(200, resp.status_code)
        assert FileShare.objects.all()[0].is_verifing() is True  # still waiting for DLP

        assert len(mail.outbox) == 2

        # notify next reviser
        assert mail.outbox[0].to[0] == self.admin.username
        assert 'please verify by clicking' in mail.outbox[0].body

        # notify share link owner
        assert mail.outbox[1].to[0] == self.user.username

        assert 'pass' in mail.outbox[1].body  # approved by user
        assert '/share/links/' in mail.outbox[1].body

    def test_can_email_receivers(self):
        assert len(FileShare.objects.all()) == 1
        assert len(mail.outbox) == 0

        fs_verify = FileShareVerify.objects.get(share_link=self.fs)
        fs_verify.DLP_status = 2
        fs_verify.save()

        self.login_as(self.user)
        resp = self.client.post(self.url, {
            't': self.fs.token,
            's': 1,
            'msg': 'xxx',
        }, HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        assert len(mail.outbox) == 2

        self.logout()

        self.login_as(self.admin)
        resp = self.client.post(self.url, {
            't': self.fs.token,
            's': 1,
            'msg': 'xxx',
        }, HTTP_X_REQUESTED_WITH='XMLHttpRequest')

        assert FileShare.objects.all()[0].pass_verify()
        # 1. sent to next reviser(admin@test.com), 2. sent to creator(test@test.com)
        # 3. send to receiver(a@a.com), 4. sent to creator(test@test.com)
        assert len(mail.outbox) == 4

        assert mail.outbox[2].to[0] == 'a@a.com'
        assert 'A file is shared to you on' in mail.outbox[2].subject
