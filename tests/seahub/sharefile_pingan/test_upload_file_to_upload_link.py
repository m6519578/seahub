import json

from django.core.urlresolvers import reverse

from seahub.share.models import (FileShare, FileShareVerify, UploadLinkShare,
                                 UploadLinkShareUploads)
from seahub.test_utils import BaseTestCase


class UploadLinkTestCase(BaseTestCase):
    def setUp(self):
        assert len(UploadLinkShare.objects.all()) == 0
        self.uls = UploadLinkShare.objects.create_upload_link_share(
            self.user.username, self.repo.id, self.folder, password='123')
        assert len(UploadLinkShare.objects.all()) == 1


class GetFileUploadUrlUlTest(UploadLinkTestCase):
    def test_get_file_upload_url(self):
        url = reverse('get_file_upload_url_ul', args=[self.uls.token]) + '?r=' + self.repo.id
        resp = self.client.get(url, HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        json_resp = json.loads(resp.content)
        assert len(json_resp['url']) > 0


class UploadFileDoneTest(UploadLinkTestCase):
    def test_upload_file_done(self):
        assert len(UploadLinkShareUploads.objects.all()) == 0

        url = reverse('upload_file_done') + '?fn=' + self.file.lstrip('/') + \
              '&repo_id=' + self.repo.id + '&p=/&t=' + self.uls.token
        resp = self.client.get(url)
        json_resp = json.loads(resp.content)
        assert json_resp['success'] is True

        assert len(UploadLinkShareUploads.objects.all()) == 1
