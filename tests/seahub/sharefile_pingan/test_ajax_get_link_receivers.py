import json
from django.core.urlresolvers import reverse

from seahub.share.models import FileShareExtraInfo
from seahub.test_utils import BaseTestCase
from .mixins import AddDownloadLinkMixin


class AJAXGetLinkReceiversTest(BaseTestCase, AddDownloadLinkMixin):
    def setUp(self):
        self.user_file_path = self.file
        self.user_repo_id = self.repo.id

        self.fs = self.add_shared_file_link()
        assert len(FileShareExtraInfo.objects.filter(share_link=self.fs)) == 1

        self.url = reverse('ajax_get_link_receivers') + '?token=' + self.fs.token

    def test_can_get(self):
        self.login_as(self.user)

        resp = self.client.get(self.url, HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        json_resp = json.loads(resp.content)
        assert len(json_resp['receivers']) == 1
        assert json_resp['receivers'][0] == 'a@a.com'

    def test_can_get_multiple(self):
        self.login_as(self.user)

        FileShareExtraInfo.objects.create(share_link=self.fs, sent_to='b@b.com',
                                          note='')

        resp = self.client.get(self.url, HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        json_resp = json.loads(resp.content)
        assert len(json_resp['receivers']) == 2
        assert json_resp['receivers'][0] == 'a@a.com'
        assert json_resp['receivers'][1] == 'b@b.com'
