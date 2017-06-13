import json
from django.core.urlresolvers import reverse

from seahub.share.models import FileShareExtraInfo
from seahub.test_utils import BaseTestCase
from .mixins import AddDownloadLinkMixin, SetupRevisersMixin


class AJAXGetLinkStatusTest(BaseTestCase, SetupRevisersMixin, AddDownloadLinkMixin):
    def setUp(self):
        self.setup_revisers()
        self.user_file_path = self.file
        self.user_repo_id = self.repo.id

        self.fs = self.add_shared_file_link()
        assert len(FileShareExtraInfo.objects.filter(share_link=self.fs)) == 1

        self.url = reverse('ajax_get_link_status') + '?token=' + self.fs.token

    def test_can_get(self):
        self.login_as(self.user)

        resp = self.client.get(self.url, HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        json_resp = json.loads(resp.content)
        assert len(json_resp['status']) == 5
        assert json_resp['password'] == '12345678'
        assert json_resp['pass_verify'] is False

    def test_invalid_token(self):
        self.url = reverse('ajax_get_link_status') + '?token=' + '123'
        self.login_as(self.user)

        resp = self.client.get(self.url, HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        json_resp = json.loads(resp.content)
        assert resp.status_code == 400
        assert json_resp['error'] == 'Share link is not found'
