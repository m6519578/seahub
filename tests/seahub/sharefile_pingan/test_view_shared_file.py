from mock import patch
import json

from django.core import mail
from django.core.urlresolvers import reverse
from django.core.management import call_command

from seahub.share.models import FileShare, FileShareVerify, FileShareDownloads
from seahub.test_utils import BaseTestCase
from seahub.share.management.commands.query_dlp_status import Command
from .mixins import SetupRevisersMixin, AddDownloadLinkMixin


class ViewSharedFileTest(BaseTestCase, SetupRevisersMixin, AddDownloadLinkMixin):
    def setUp(self):
        self.user_repo_id = self.repo.id
        self.user_dir_path = self.folder
        self.user_file_path = self.file

        self.setup_revisers()
        # Add file share and file share verify
        self.fs = self.add_shared_file_link()
        self.url = reverse('view_shared_file', args=[self.fs.token])

    def test_anonymous_user(self):
        """Redirect to login page for anonymous user.
        """
        resp = self.client.get(self.url)
        self.assertEqual(302, resp.status_code)
        assert "next=/f/%s/" % self.fs.token in resp.get('location')

    def test_department_head(self):
        """Department head can view this encrypt shared link without provide
        password.
        """
        self.login_as(self.user)

        resp = self.client.get(self.url)
        self.assertEqual(200, resp.status_code)
        self.assertTemplateUsed(resp, 'shared_file_view.html')
        assert resp.context['skip_encrypted'] is True
        assert resp.context['need_verify'] is True
        assert resp.context['user_pass'] is False
        assert resp.context['user_veto'] is False

        self.logout()

    def test_reviser_1(self):
        """Reviser 1 can view this encrypt shared link without provide
        password.
        """
        self.login_as(self.admin)

        resp = self.client.get(self.url)
        self.assertEqual(200, resp.status_code)
        self.assertTemplateUsed(resp, 'shared_file_view.html')
        assert resp.context['skip_encrypted'] is True
        assert resp.context['need_verify'] is True
        assert resp.context['user_pass'] is False
        assert resp.context['user_veto'] is False

        self.logout()

    def test_view_verified_file(self):
        """A verified shared link can be viewed by anyone.
        """
        fs_v = FileShareVerify.objects.get(share_link=self.fs)
        fs_v.DLP_status = 1
        fs_v.department_head_status = 1
        fs_v.reviser_status = 1
        fs_v.save()

        resp = self.client.get(self.url)
        self.assertEqual(200, resp.status_code)
        self.assertTemplateUsed(resp, 'share_access_validation_for_pingan.html')
        assert resp.context['view_name'] == 'view_shared_file'
        assert 'skip_encrypted' not in resp.context.keys()

        # post password, first wrong, second correct
        resp = self.client.post(self.url, {
            'password': 'bad passwd',
        })
        assert resp.context['password'] == 'bad passwd'
        self.assertEqual(200, resp.status_code)
        self.assertTemplateUsed(resp, 'share_access_validation_for_pingan.html')

        resp = self.client.post(self.url, {
            'password': '12345678',
        })
        self.assertEqual(200, resp.status_code)
        self.assertTemplateUsed(resp, 'shared_file_view.html')

    def test_download_shared_file(self):
        assert len(FileShareDownloads.objects.all()) == 0

        # verify a shared link
        fs_v = FileShareVerify.objects.get(share_link=self.fs)
        fs_v.DLP_status = 1
        fs_v.department_head_status = 1
        fs_v.reviser_status = 1
        fs_v.save()

        # enter password
        resp = self.client.post(self.url, {
            'password': '12345678',
        })

        # download a shared link
        resp = self.client.get(self.url + '?dl=1')
        self.assertEqual(302, resp.status_code)
        assert "8082" in resp.get('location')

        assert len(FileShareDownloads.objects.all()) == 1
