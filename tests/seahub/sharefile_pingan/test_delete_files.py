import json
from django.core.urlresolvers import reverse

from seahub.share.models import FileShare
from seahub.test_utils import BaseTestCase
from .mixins import AddDownloadLinkMixin

class ViewSharedFileTest(BaseTestCase, AddDownloadLinkMixin):
    def setUp(self):
        self.user_repo_id = self.repo.id
        self.user_dir_path = self.folder
        self.user_file_path = self.file

        # Add file share and file share verify
        self.fs = self.add_shared_file_link()

    def test_delete_file(self):
        """Remove shared link when file is deleted.
        """
        self.login_as(self.user)
        assert len(FileShare.objects.all()) == 1

        url = reverse('delete_dir', args=[self.repo.id]) + '?parent_dir=/&name=' + self.file.lstrip('/')
        resp = self.client.post(url, HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        json_resp = json.loads(resp.content)
        assert json_resp['success'] is True

        assert len(FileShare.objects.all()) == 0

    def test_delete_files(self):
        """Remove shared link when files are deleted.
        """
        self.login_as(self.user)
        assert len(FileShare.objects.all()) == 1

        url = reverse('delete_dirents', args=[self.repo.id]) + '?parent_dir=/'
        resp = self.client.post(url, {
            'dirents_names': [self.file.lstrip('/')]
        }, HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        json_resp = json.loads(resp.content)
        assert len(json_resp['deleted']) == 1

        assert len(FileShare.objects.all()) == 0
