# -*- coding: utf-8 -*-

from django.conf import settings
from django.http import HttpResponseRedirect, Http404
from django.shortcuts import render_to_response, get_object_or_404
from django.template import RequestContext
from django.utils.http import urlquote
from django.utils.translation import ugettext as _

from seahub.auth import REDIRECT_FIELD_NAME
from seahub.share.models import (FileShare, set_share_link_access,
                                 check_share_link_access, FileShareVerify,
                                 FileShareReviserInfo)
from seahub.share.forms import SharedLinkPasswordForm, CaptchaSharedLinkPasswordForm
from seahub.share.utils import (incr_share_link_decrypt_failed_attempts,
                                clear_share_link_decrypt_failed_attempts,
                                show_captcha_share_link_password_form,
                                enable_share_link_verify_code,
                                get_unusable_verify_code)
from seahub.utils import render_error
from seahub.utils.ip import get_remote_ip

def share_link_approval_for_pingan(func):
    """Decorator for share link approval test for PingAn Group.
    When a share link does not pass verify, only verifier can view the link,
    no mater encrypted or expired.
    """
    def _decorated(request, token, *args, **kwargs):
        fileshare = get_object_or_404(FileShare, token=token)
        if fileshare.pass_verify():
            if fileshare.is_expired():
                raise Http404

            return func(request, fileshare, *args, **kwargs)

        # verifier can view encrypted shared link without need to enter
        # password if this shared link is not pass verify.
        skip_encrypted = False

        # If a shared link is not pass verify, then it need to be verified and
        # can only be viewed by verifiers.
        need_verify = False

        user_pass, user_veto = False, False
        if request.user.is_anonymous():
            # show login page
            path = urlquote(request.get_full_path())
            tup = settings.LOGIN_URL, REDIRECT_FIELD_NAME, path
            return HttpResponseRedirect('%s?%s=%s' % tup)
        else:
            revisers = FileShareReviserInfo.objects.get_reviser_emails(fileshare)
            req_user = request.user.username
            if req_user in revisers:
                fs_v = FileShareVerify.objects.get(share_link=fileshare)
                if req_user == revisers[0]:
                    if fs_v.department_head_pass():
                        user_pass = True
                    if fs_v.department_head_veto():
                        user_veto = True

                elif req_user == revisers[1]:
                    if fs_v.comanager_head_pass():
                        user_pass = True
                    if fs_v.comanager_head_veto():
                        user_veto = True

                elif req_user == revisers[2] or req_user == revisers[3]:
                    if fs_v.revisers_pass():
                        user_pass = True
                    if fs_v.revisers_veto():
                        user_veto = True

                skip_encrypted = True
                need_verify = True
                kwargs.update({
                    'skip_encrypted': skip_encrypted,
                    'need_verify': need_verify,
                    'user_pass': user_pass,
                    'user_veto': user_veto,
                })
                return func(request, fileshare, *args, **kwargs)
            else:
                return render_error(request, _(u'权限不足：你无法访问该文件。'))

    return _decorated

def share_link_passwd_check_for_pingan(func):
    """Decorator for share link password check, show captcah if too many
    failed attempts.

    Also show email verify code if `ENABLE_SHARE_LINK_VERIFY_CODE = True`
    """
    def _decorated(request, fileshare, *args, **kwargs):
        token = fileshare.token
        skip_encrypted = kwargs.get('skip_encrypted', False)
        if skip_encrypted or not fileshare.is_encrypted() or \
           check_share_link_access(request, token) is True:
            # no check for un-encrypt shared link, or if `skip_encrypted` in
            # keyword arguments or password is already stored in session
            return func(request, fileshare, *args, **kwargs)

        d = {'token': token, 'view_name': func.__name__,
             'enable_share_link_verify_code': enable_share_link_verify_code()}
        ip = get_remote_ip(request)
        validation_tmpl = 'share_access_validation_for_pingan.html'
        if request.method == 'POST':
            post_values = request.POST.copy()
            post_values['enc_password'] = fileshare.password
            post_values['token'] = token
            if not enable_share_link_verify_code():
                # set verify code to random string to make form validation
                # pass
                post_values['verify_code'] = get_unusable_verify_code()

            if show_captcha_share_link_password_form(ip):
                form = CaptchaSharedLinkPasswordForm(post_values)
            else:
                form = SharedLinkPasswordForm(post_values)
            d['form'] = form
            if form.is_valid():
                set_share_link_access(request, token)
                clear_share_link_decrypt_failed_attempts(ip)

                return func(request, fileshare, *args, **kwargs)
            else:
                incr_share_link_decrypt_failed_attempts(ip)
                d.update({'password': request.POST.get('password', ''),
                          'verify_code': request.POST.get('verify_code', '')})
                return render_to_response(validation_tmpl, d,
                                          context_instance=RequestContext(request))
        else:
            if show_captcha_share_link_password_form(ip):
                d.update({'form': CaptchaSharedLinkPasswordForm})
            return render_to_response(validation_tmpl, d,
                                      context_instance=RequestContext(request))
    return _decorated
