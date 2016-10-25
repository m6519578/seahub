from django.core.urlresolvers import reverse
from django.core import mail

from seahub.test_utils import BaseTestCase
from seahub.share.models import FileShare
from .mixins import SetupRevisersMixin, AddDownloadLinkMixin


class ListFileShareVerifyTest(BaseTestCase, SetupRevisersMixin, AddDownloadLinkMixin):
    def setUp(self):
        self.user_repo_id = self.repo.id
        self.user_dir_path = self.folder
        self.user_file_path = self.file
        self.fs = self.add_shared_file_link()

        self.url = reverse('list_file_share_verify')

    def test_can_list(self):
        self.setup_revisers()
        self.login_as(self.admin)

        resp = self.client.get(self.url)
        self.assertEqual(200, resp.status_code)
        assert len(resp.context['verifing_links']) == 1
        assert resp.context['verifing_links'][0].username == self.user.username

    def test_can_list_by_reviser_map(self):
        self.setup_reviser_map()
        self.login_as(self.user)

        resp = self.client.get(self.url)
        self.assertEqual(200, resp.status_code)
        assert len(resp.context['verifing_links']) == 1
        assert resp.context['verifing_links'][0].username == self.user.username
