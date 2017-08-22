# -*- coding: utf-8 -*-
import json

from django.core.urlresolvers import reverse
from seahub.test_utils import BaseTestCase

class ShareLinksTest(BaseTestCase):

    def setUp(self):
        self.url = reverse('api-v2.1-approval-chain')

    def tearDown(self):
        pass

    def test_permission(self):
        self.login_as(self.user)
        resp = self.client.get(self.url)
        assert resp.status_code == 403

    def test_put(self):
        self.login_as(self.admin)

        chain1 = 'dev1 <-> a@pingan.com.cn -> b@pingan.com.cn | c@pingan.com.cn'
        chain2 = 'dev2 <-> a@pingan.com.cn -> b@pingan.com.cn -> c@pingan.com.cn'

        resp = self.client.put(self.url, "chain=%s&chain=%s" % (chain1, chain2),
                               'application/x-www-form-urlencoded')

        json_resp = json.loads(resp.content)
        assert len(json_resp['failed']) == 0
        assert len(json_resp['success']) == 2

    def test_get(self):
        self.login_as(self.admin)
        resp = self.client.get(self.url)
        json_resp = json.loads(resp.content)
        assert json_resp['count'] == 0

        chain1 = 'dev1 <-> a@pingan.com.cn -> b@pingan.com.cn | c@pingan.com.cn'
        resp = self.client.put(self.url, "chain=%s" % (chain1),
                               'application/x-www-form-urlencoded')

        resp = self.client.get(self.url)
        json_resp = json.loads(resp.content)
        assert json_resp['count'] == 1
