# -*- coding: utf-8 -*-
import json
import datetime
import time

from django.core.urlresolvers import reverse
from django.core import mail

from seahub.share.models import (FileShare, FileShareVerify,
                                 FileShareDownloads, FileShareReviserInfo)
from seahub.test_utils import BaseTestCase
from .mixins import SetupRevisersMixin, AddDownloadLinkMixin

class RemindRevisersTest(BaseTestCase, SetupRevisersMixin, AddDownloadLinkMixin):
    def setUp(self):
        self.user_repo_id = self.repo.id
        self.user_dir_path = self.folder
        self.user_file_path = self.file

        self.setup_revisers()
        # modify file share reivers
        assert len(FileShareReviserInfo.objects.all()) == 1
        info = FileShareReviserInfo.objects.all()[0]
        info.reviser1_name = self.user.username
        info.reviser1_account = self.user.username
        info.reviser1_email = self.user.username
        info.save()

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
        assert len(json_resp['sent']) == 2
        self.assertEqual(len(mail.outbox), 2)

        # department head verify a shared link
        fs_v = FileShareVerify.objects.get(share_link=self.fs)
        fs_v.department_head_status = 1
        fs_v.save()

        resp = self.client.post(reverse('ajax_remind_revisers'), {
            'token': self.fs.token,
        }, HTTP_X_REQUESTED_WITH='XMLHttpRequest')

        self.assertEqual(200, resp.status_code)
        json_resp = json.loads(resp.content)
        assert len(json_resp['sent']) == 1


