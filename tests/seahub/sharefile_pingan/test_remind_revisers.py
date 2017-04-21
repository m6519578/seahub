# -*- coding: utf-8 -*-
import json
import datetime
import time

from django.core.urlresolvers import reverse
from django.core import mail

from seahub.share.models import (FileShare, FileShareVerify,
                                 FileShareDownloads, FileShareReviserChain)
from seahub.test_utils import BaseTestCase
from .mixins import SetupRevisersMixin, AddDownloadLinkMixin

class RemindRevisersTest(BaseTestCase, SetupRevisersMixin, AddDownloadLinkMixin):
    def setUp(self):
        self.user_repo_id = self.repo.id
        self.user_dir_path = self.folder
        self.user_file_path = self.file

        self.setup_revisers()
        assert len(FileShareReviserChain.objects.all()) == 1

        # Add file share and file share verify
        self.fs = self.add_shared_file_link()

    def test_can_remind(self):
        self.login_as(self.user)
        self.assertEqual(len(mail.outbox), 0)

        resp = self.client.post(reverse('ajax_remind_revisers'), {
            'token': self.fs.token,
        }, HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        self.assertEqual(200, resp.status_code)
        json_resp = json.loads(resp.content)
        assert len(json_resp['sent']) == 1
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to[0], self.user.username)

        # 4 revisers verified the shared link
        fs_v = FileShareVerify.objects.get(share_link=self.fs)
        fs_v.line_manager_status = 1
        fs_v.department_head_status = 1
        fs_v.comanager_head_status = 1
        fs_v.compliance_owner_status = 1
        fs_v.save()

        resp = self.client.post(reverse('ajax_remind_revisers'), {
            'token': self.fs.token,
        }, HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        self.assertEqual(400, resp.status_code)
