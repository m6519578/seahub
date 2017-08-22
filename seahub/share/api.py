# -*- coding: utf-8 -*-
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle
from seahub.api2.utils import api_error
from seahub.base.accounts import User
from seahub.share.models import ApprovalChain, approval_chain_str2list
from seahub.utils import is_valid_email


class ApprovalChainView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )
    throttle_classes = (UserRateThrottle, )

    def get(self, request):
        """List department approval chain.

        e.g.

        curl -v -H 'Authorization: Token 5f7435e5e585f935b84067bd0b6088cf8af9f6ac' -H 'Accept: application/json; indent=4' http://127.0.0.1:8000/api/v2.1/admin/approval-chain/

        """
        qs = ApprovalChain.objects.values_list('department',
                                               flat=True).distinct()

        return Response({'count': len(qs)})

    def put(self, request):
        """Add or update department approval chain.

        e.g.

        curl -X PUT -d "chain=测试部门1<->a@pingan.com.cn->b@pingan.com.cn->c@pingan.com.cn | d@pingan.com.cn&chain=测试部门2<->a@pingan.com.cn->b@pingan.com.cn->c@pingan.com.cn" -v -H 'Authorization: Token 5f7435e5e585f935b84067bd0b6088cf8af9f6ac' -H 'Accept: application/json; indent=4' http://127.0.0.1:8000/api/v2.1/admin/approval-chain/

        """
        chain_list = request.data.getlist('chain', None)
        if not chain_list:
            error_msg = 'chain invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        success = []
        failed = []
        for ele in chain_list:
            splits = ele.split('<->')
            if len(splits) != 2:
                failed.append(ele)
                continue

            dept = splits[0].strip()
            chain = splits[1].strip()
            if not dept or not chain:
                failed.append(ele)
                continue

            # remove duplicated records
            ApprovalChain.objects.filter(department=dept).delete()

            chain_list = approval_chain_str2list(chain)
            for e in chain_list:
                if isinstance(e, basestring):
                    if not is_valid_email(e):
                        failed.append(ele)
                        continue
                    try:
                        u = User.objects.get(email=e)
                        if not u.is_active:
                            failed.append(ele)
                            continue
                    except User.DoesNotExist:
                        failed.append(ele)
                        continue
                else:
                    for x in e[1:]:
                        if not is_valid_email(x):
                            failed.append(ele)
                            continue
                    try:
                        u = User.objects.get(email=x)
                        if not u.is_active:
                            failed.append(ele)
                            continue
                    except User.DoesNotExist:
                        failed.append(ele)
                        continue

            ApprovalChain.objects.create_chain(dept, chain_list)
            success.append(ele)

        result = {
            'success': success,
            'failed': failed,
        }
        return Response(result)
