from collections import namedtuple

from seahub.share.constants import STATUS_VERIFING, STATUS_PASS, STATUS_VETO
from seahub.share.models import (FileShareApprovalStatus, FileShare,
                                 ApprovalChain, get_chain_next_step)
from seahub.profile.models import Profile, DetailedProfile
from seahub.test_utils import BaseTestCase


class FileShareApprovalStatusManagerTest(BaseTestCase):
    def setUp(self):
        self.dept = 'dept1'
        self.chain_list = ['a@pingan.com.cn', ('op_or', 'b@pingan.com.cn',
                                               'c@pingan.com.cn'), 'd@pingan.com.cn']

        ApprovalChain.objects.create_chain(self.dept, self.chain_list)

        Profile.objects.add_or_update(self.user.username, '', '')
        DetailedProfile.objects.add_detailed_profile(self.user.username,
                                                     self.dept, '')

        self.fs = FileShare.objects.create_file_link(
            self.user.username, self.repo.id, self.file)

        fs_v = FileShareApprovalStatus(share_link=self.fs, email='DLP')
        fs_v.save()

    def test_get_chain_status_by_share_link(self):
        chain = FileShareApprovalStatus.objects.get_chain_status_by_share_link(self.fs)

        assert len(chain) == 4
        assert chain[0].status == STATUS_VERIFING


class GetChainNextStepTest(BaseTestCase):
    def test_get(self):
        stat_obj = namedtuple('ApprovalStatusTuple', ['email', 'status'])

        # a -> b|c -> a
        chain_status_list = [
            stat_obj(email='dlp', status=2),
            stat_obj(email='a@pingan.com.cn', status=1),
            ('op_or', stat_obj(email='b@pingan.com.cn', status=0),
             stat_obj(email='c@pingan.com.cn', status=0),
            ),
            stat_obj(email='a@pingan.com.cn', status=1),
        ]

        next = get_chain_next_step(chain_status_list, 'a@pingan.com.cn')
        assert next[0] == 'op_or'
        assert next[1].email == 'b@pingan.com.cn'
        assert next[2].email == 'c@pingan.com.cn'

        # a -> b -> c -> d
        chain_status_list = [
            stat_obj(email='dlp', status=2),
            stat_obj(email='a@pingan.com.cn', status=1),
            stat_obj(email='b@pingan.com.cn', status=0),
            stat_obj(email='c@pingan.com.cn', status=0),
            stat_obj(email='d@pingan.com.cn', status=0),
        ]

        next = get_chain_next_step(chain_status_list, 'a@pingan.com.cn')
        assert next.email == 'b@pingan.com.cn'

        # a -> a -> a -> d
        chain_status_list = [
            stat_obj(email='dlp', status=2),
            stat_obj(email='a@pingan.com.cn', status=1),
            stat_obj(email='a@pingan.com.cn', status=1),
            stat_obj(email='a@pingan.com.cn', status=1),
            stat_obj(email='d@pingan.com.cn', status=0),
        ]

        next = get_chain_next_step(chain_status_list, 'a@pingan.com.cn')
        assert next.email == 'd@pingan.com.cn'

        # a -> a -> a -> b|d
        chain_status_list = [
            stat_obj(email='dlp', status=2),
            stat_obj(email='a@pingan.com.cn', status=1),
            stat_obj(email='a@pingan.com.cn', status=1),
            stat_obj(email='a@pingan.com.cn', status=1),
            ('op_or', stat_obj(email='b@pingan.com.cn', status=0),
             stat_obj(email='d@pingan.com.cn', status=0),
         ),
        ]
        next = get_chain_next_step(chain_status_list, 'a@pingan.com.cn')
        assert next[0] == 'op_or'
        assert next[1].email == 'b@pingan.com.cn'
        assert next[2].email == 'd@pingan.com.cn'

        # a|b|c|d
        chain_status_list = [
            stat_obj(email='dlp', status=2),
            ('op_or',
             stat_obj(email='a@pingan.com.cn', status=1),
             stat_obj(email='b@pingan.com.cn', status=0),
             stat_obj(email='c@pingan.com.cn', status=0),
             stat_obj(email='d@pingan.com.cn', status=0),
         ),
        ]
        next = get_chain_next_step(chain_status_list, 'a@pingan.com.cn')
        assert next is None

        # a
        chain_status_list = [
            stat_obj(email='dlp', status=2),
            stat_obj(email='a@pingan.com.cn', status=1),
        ]
        next = get_chain_next_step(chain_status_list, 'a@pingan.com.cn')
        assert next is None
