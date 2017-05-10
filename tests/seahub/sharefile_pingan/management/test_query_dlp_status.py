from mock import patch
import json

from django.core import mail
from django.core.urlresolvers import reverse
from django.core.management import call_command

from seahub.share.models import FileShare, FileShareVerify
from seahub.test_utils import BaseTestCase
from seahub.share.management.commands.query_dlp_status import Command
from ..mixins import SetupRevisersMixin, AddDownloadLinkMixin


class CommandTest(BaseTestCase, SetupRevisersMixin, AddDownloadLinkMixin):
    def setUp(self):
        self.url = reverse('ajax_get_download_link')

        self.user_repo_id = self.repo.id
        self.user_dir_path = self.folder
        self.user_file_path = self.file
        self.login_as(self.user)

        self.setup_revisers()

        # Add file share and file share verify
        self.fs = self.add_shared_file_link()

    @patch.object(Command, 'query_dlp_status')
    def test_dlp_pass(self, mock_query_dlp_status):
        assert len(mail.outbox) == 0
        mock_query_dlp_status.return_value = 1

        call_command('query_dlp_status')
        assert len(mail.outbox) == 2
        assert 'Please verify new share link.' == mail.outbox[0].subject
        assert 'class="dlp-msg"' not in mail.outbox[0].body
        assert 'Verification status of your share link.' == mail.outbox[1].subject
        assert 'passed by DLP' in mail.outbox[1].body

    @patch.object(Command, 'query_dlp_status')
    def test_dlp_rejected(self, mock_query_dlp_status):
        assert len(mail.outbox) == 0
        mock_query_dlp_status.return_value = 2

        call_command('query_dlp_status')

        assert len(mail.outbox) == 2
        assert 'Please verify new share link.' == mail.outbox[0].subject
        assert 'class="dlp-msg"' in mail.outbox[0].body
        assert 'Verification status of your share link.' == mail.outbox[1].subject
        assert 'rejected by DLP' in mail.outbox[1].body
