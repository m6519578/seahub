import json

from django.core.urlresolvers import reverse

from seahub.share.models import FileShare, FileShareVerify
from seahub.test_utils import BaseTestCase


class AJAXGetDownloadLinkTest(BaseTestCase):
    def setUp(self):
        self.url = reverse('ajax_get_download_link')

        self.user_repo_id = self.repo.id
        self.user_dir_path = self.folder
        self.user_file_path = self.file
        self.login_as(self.user)

    def test_can_generate(self):
        """User generate a shared link, record this link to `FielShareVerify`
        to be verified. Then create a symble link at DLP scan directory for
        DLP to scan.

        This link is not available until verified by both DLP and verifiers.
        """
        assert len(FileShare.objects.all()) == 0
        assert len(FileShareVerify.objects.all()) == 0

        data = {
            'repo_id': self.user_repo_id,
            'p': self.user_file_path,
            'type': 'f',
            'use_passwd': '1',
            'passwd': '12345678',
            'expire_days': 3,
        }
        resp = self.client.post(self.url, data, HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        json_resp = json.loads(resp.content)
        assert json_resp['download_link'] == ''
        assert json_resp['token'] == ''
        assert len(FileShare.objects.all()) == 1
        assert len(FileShareVerify.objects.all()) == 1

    def test_can_list(self):
        """List a download link for a file.
        """
        data = {
            'repo_id': self.user_repo_id,
            'p': self.user_file_path,
            'type': 'f',
            'use_passwd': '1',
            'passwd': '12345678',
            'expire_days': 3,
        }
        resp = self.client.post(self.url, data, HTTP_X_REQUESTED_WITH='XMLHttpRequest')

        resp = self.client.get(self.url + '?repo_id=' + self.user_repo_id +
                               '&type=f&p=' + self.user_file_path,
                               HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        json_resp = json.loads(resp.content)
        assert json_resp['status'] == '0'
        assert 'Your share link is waiting for verify.' in json_resp['status_str']
        assert json_resp['token'] == ''
        assert json_resp['download_link'] == ''

        fs_v = FileShareVerify.objects.all()[0]
        fs_v.DLP_status = 1
        fs_v.department_head_status = 1
        fs_v.reviser_status = 1
        fs_v.save()

        resp = self.client.get(self.url + '?repo_id=' + self.user_repo_id +
                               '&type=f&p=' + self.user_file_path,
                               HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        json_resp = json.loads(resp.content)
        assert len(json_resp['token']) == 10
        assert json_resp['password'] == '12345678'
