from mock import patch
import json
from django.core.urlresolvers import reverse

from seahub.test_utils import BaseTestCase


class FileEditSubmitTest(BaseTestCase):
    @patch('seahub.signals.file_edited.send')
    def test_send_signal_after_edit(self, mock_file_edited_send):
        self.login_as(self.user)

        self.url = reverse('file_edit', args=[self.repo.id]) + '?p=' + self.file

        resp = self.client.post(self.url, {
            'content': 'xxx',
            'encoding': 'utf-8',
        })
        json_resp = json.loads(resp.content)
        assert len(json_resp['href']) > 0
        self.assertTrue(mock_file_edited_send.called)
