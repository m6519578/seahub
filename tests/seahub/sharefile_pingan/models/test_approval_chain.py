from seahub.share.models import ApprovalChain
from seahub.test_utils import BaseTestCase


class ApprovalChainManagerTest(BaseTestCase):
    def setUp(self):
        self.dept = 'dept1'
        self.chain_list = ['a@pingan.com.cn', ('op_or', 'b@pingan.com.cn',
                                               'c@pingan.com.cn'), 'd@pingan.com.cn']

        ret = ApprovalChain.objects.create_chain(self.dept, self.chain_list)
        assert ret is True

        self.dept = 'dept2'
        self.chain_list = ['a@pingan.com.cn', 'a@pingan.com.cn',
                           'a@pingan.com.cn', ('op_or', 'b@pingan.com.cn',
                                               'c@pingan.com.cn')]

        ret = ApprovalChain.objects.create_chain(self.dept, self.chain_list)

        self.dept = 'dept3'
        self.chain_list = ['a@pingan.com.cn', 'a@pingan.com.cn',
                           'a@pingan.com.cn', 'b@pingan.com.cn']

        ret = ApprovalChain.objects.create_chain(self.dept, self.chain_list)

        self.dept = 'dept4'
        self.chain_list = [('op_or', 'a@pingan.com.cn',
                            'b@pingan.com.cn', 'c@pingan.com.cn')]

        ret = ApprovalChain.objects.create_chain(self.dept, self.chain_list)

    # def test_create_chain(self):
    #     pass

    def test_get_by_department1(self):
        ret = ApprovalChain.objects.get_by_department('dept1')
        print ret
        assert 'a@pingan.com.cn' in ret
        assert 'b@pingan.com.cn' not in ret
        assert ('op_or', 'b@pingan.com.cn', 'c@pingan.com.cn') in ret
        assert 'd@pingan.com.cn' in ret

    def test_get_by_department2(self):
        ret = ApprovalChain.objects.get_by_department('dept2')
        print ret

        assert 'a@pingan.com.cn' in ret
        assert 'b@pingan.com.cn' not in ret
        assert ('op_or', 'b@pingan.com.cn', 'c@pingan.com.cn') in ret

    def test_get_by_department3(self):
        ret = ApprovalChain.objects.get_by_department('dept3')
        print ret

        assert 'a@pingan.com.cn' in ret
        assert 'b@pingan.com.cn' in ret

    def test_get_by_department4(self):
        ret = ApprovalChain.objects.get_by_department('dept4')
        print ret

        assert 'a@pingan.com.cn' not in ret
        assert 'b@pingan.com.cn' not in ret
        assert ('op_or', 'a@pingan.com.cn', 'b@pingan.com.cn', 'c@pingan.com.cn') in ret

    def test_get_by_department_flat(self):
        ret = ApprovalChain.objects.get_by_department('dept1', flat=True)
        assert 'a@pingan.com.cn' in ret
        assert 'b@pingan.com.cn' in ret

        ret = ApprovalChain.objects.get_by_department('dept2', flat=True)
        assert 'a@pingan.com.cn' in ret
        assert 'b@pingan.com.cn' in ret
        assert 'c@pingan.com.cn' in ret

        ret = ApprovalChain.objects.get_by_department('dept3', flat=True)
        assert 'a@pingan.com.cn' in ret
        assert 'b@pingan.com.cn' in ret

        ret = ApprovalChain.objects.get_by_department('dept4', flat=True)
        assert 'a@pingan.com.cn' in ret
        assert 'b@pingan.com.cn' in ret
        assert 'c@pingan.com.cn' in ret




# class ApprovalChainTest(BaseTestCase):
#     pass
