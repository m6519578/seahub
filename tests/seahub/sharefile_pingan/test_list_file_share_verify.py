from django.core.urlresolvers import reverse
from django.core import mail

from seahub.test_utils import BaseTestCase
from seahub.share.models import FileShare, FileShareVerify
from .mixins import SetupRevisersMixin, AddDownloadLinkMixin


class ListFileShareVerifyTest(BaseTestCase, SetupRevisersMixin, AddDownloadLinkMixin):
    def setUp(self):
        self.user_repo_id = self.repo.id
        self.user_dir_path = self.folder
        self.user_file_path = self.file
        self.fs = self.add_shared_file_link()

        self.url = reverse('list_file_share_verify')

    def test_dlp_verifying(self):
        self.setup_revisers()

        self.login_as(self.user)
        resp = self.client.get(self.url)
        self.assertEqual(200, resp.status_code)
        assert len(resp.context['verifing_links']) == 0

        self.logout()

        self.login_as(self.admin)
        resp = self.client.get(self.url)
        self.assertEqual(200, resp.status_code)
        assert len(resp.context['verifing_links']) == 0

    def test_dlp_pass(self):
        self.setup_revisers()
        fs_verify = FileShareVerify.objects.get(share_link=self.fs)
        fs_verify.DLP_status = 1
        fs_verify.save()

        self.login_as(self.user)
        resp = self.client.get(self.url)
        self.assertEqual(200, resp.status_code)
        assert len(resp.context['verifing_links']) == 1
        assert resp.context['verifing_links'][0].username == self.user.username
        self.logout()

        self.login_as(self.admin)
        resp = self.client.get(self.url)
        self.assertEqual(200, resp.status_code)
        assert len(resp.context['verifing_links']) == 0

    def test_dlp_veto(self):
        self.setup_revisers()
        fs_verify = FileShareVerify.objects.get(share_link=self.fs)
        fs_verify.DLP_status = 2
        fs_verify.save()

        self.login_as(self.user)
        resp = self.client.get(self.url)
        self.assertEqual(200, resp.status_code)
        assert len(resp.context['verifing_links']) == 1

        self.logout()

        self.login_as(self.admin)
        resp = self.client.get(self.url)
        self.assertEqual(200, resp.status_code)
        assert len(resp.context['verifing_links']) == 0

    def test_user1_pass(self):
        self.setup_revisers()
        fs_verify = FileShareVerify.objects.get(share_link=self.fs)
        fs_verify.DLP_status = 1
        fs_verify.line_manager_status = 1
        fs_verify.department_head_status = 1
        fs_verify.save()

        self.login_as(self.user)
        resp = self.client.get(self.url)
        self.assertEqual(200, resp.status_code)
        assert len(resp.context['verifing_links']) == 0
        assert len(resp.context['verified_links']) == 1

        self.logout()

        self.login_as(self.admin)
        resp = self.client.get(self.url)
        self.assertEqual(200, resp.status_code)
        assert len(resp.context['verifing_links']) == 1
        assert len(resp.context['verified_links']) == 0

    def test_user1_veto(self):
        self.setup_revisers()
        fs_verify = FileShareVerify.objects.get(share_link=self.fs)
        fs_verify.DLP_status = 1
        fs_verify.line_manager_status = 2
        fs_verify.department_head_status = 2
        fs_verify.save()

        self.login_as(self.user)
        resp = self.client.get(self.url)
        self.assertEqual(200, resp.status_code)
        assert len(resp.context['verifing_links']) == 0
        assert len(resp.context['verified_links']) == 1

        self.logout()

        self.login_as(self.admin)
        resp = self.client.get(self.url)
        self.assertEqual(200, resp.status_code)
        assert len(resp.context['verifing_links']) == 0
        assert len(resp.context['verified_links']) == 0

    def test_can_list_by_reviser_map(self):
        self.setup_reviser_map()
        fs_verify = FileShareVerify.objects.get(share_link=self.fs)
        fs_verify.DLP_status = 1
        fs_verify.save()

        self.login_as(self.user)
        resp = self.client.get(self.url)
        self.assertEqual(200, resp.status_code)
        assert len(resp.context['verifing_links']) == 1
        assert resp.context['verifing_links'][0].username == self.user.username
