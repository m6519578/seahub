# -*- coding: utf-8 -*-

from django.conf import settings
from django.http import HttpResponseRedirect, Http404
from django.shortcuts import render_to_response, get_object_or_404
from django.template import RequestContext
from django.utils.http import urlquote
from django.utils.translation import ugettext as _

from seahub.auth import REDIRECT_FIELD_NAME
from seahub.base.templatetags.seahub_tags import email2nickname
from seahub.share.constants import STATUS_VETO, STATUS_PASS
from seahub.share.models import (FileShare, set_share_link_access,
                                 check_share_link_access, FileShareExtraInfo,
                                 FileShareApprovalStatus, get_chain_step_sibling_type)
from seahub.share.forms import SharedLinkPasswordForm, CaptchaSharedLinkPasswordForm
from seahub.share.utils import (incr_share_link_decrypt_failed_attempts,
                                clear_share_link_decrypt_failed_attempts,
                                show_captcha_share_link_password_form,
                                enable_share_link_verify_code,
                                get_unusable_verify_code)
from seahub.share.signals import file_shared_link_decrypted
from seahub.utils import render_error
from seahub.utils.ip import get_remote_ip

def share_link_approval_for_pingan(func):
    """Decorator for share link approval test for PingAn Group.
    When a share link does not pass verify, only verifier can view the link,
    no mater encrypted or expired.
    """
    def _decorated(request, token, *args, **kwargs):
        req_user = request.user.username
        fileshare = get_object_or_404(FileShare, token=token)

        chain = fileshare.get_approval_chain(flat=True)
        if fileshare.pass_verify() and req_user not in chain:
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
        show_dlp_veto_msg, other_pass, other_veto, other_info = False, False, False, None
        if request.user.is_anonymous():
            # show login page
            path = urlquote(request.get_full_path())
            tup = settings.LOGIN_URL, REDIRECT_FIELD_NAME, path
            return HttpResponseRedirect('%s?%s=%s' % tup)
        else:
            if len(chain) == 0:
                return render_error(request, _(u'权限不足：你无法访问该文件。'))

            if req_user not in chain:
                return render_error(request, _(u'权限不足：你无法访问该文件。'))

            chain_status_list = FileShareApprovalStatus.objects.\
                                get_chain_status_by_share_link(fileshare)
            show_dlp_veto_msg = chain_status_list[0].status == STATUS_VETO

            for obj in chain_status_list:
                if get_chain_step_sibling_type(obj):  # siblings
                    sibling_type = obj[0]  # can be 'op_or' or 'op_and'
                    siblings = obj[1:]
                    if req_user not in [x.email for x in siblings]:
                        # request user is not in current step, go to next step
                        continue

                    # User is in the current step, find the sibling who
                    # approve or reject.
                    target_sibling = None
                    for sibling_obj in siblings:
                        if sibling_obj.status == STATUS_PASS or \
                           sibling_obj.status == STATUS_VETO:
                            target_sibling = sibling_obj

                    if target_sibling is not None:
                        if req_user == target_sibling.email:
                            # approved or rejected by me
                            user_pass = target_sibling.status == STATUS_PASS
                            user_veto = target_sibling.status == STATUS_VETO
                        else:
                            # approved or rejected by others
                            other_pass = target_sibling.status == STATUS_PASS
                            other_veto = target_sibling.status == STATUS_VETO
                            other_info = '%s (%s)' % (
                                email2nickname(target_sibling.email),
                                target_sibling.email)
                else:  # no siblings
                    if req_user == obj.email:
                        user_pass = obj.status == STATUS_PASS
                        user_veto = obj.status == STATUS_VETO

            skip_encrypted = True
            need_verify = True
            extra_info = FileShareExtraInfo.objects.filter(share_link=fileshare)
            if len(extra_info) == 0:
                share_to = ''
                note = ''
            else:
                share_to = ', '.join([e.sent_to for e in extra_info])
                note = extra_info[0].note
            kwargs.update({
                'skip_encrypted': skip_encrypted,
                'need_verify': need_verify,
                'user_pass': user_pass,
                'user_veto': user_veto,
                'other_pass': other_pass,
                'other_veto': other_veto,
                'other_info': other_info,
                'share_to': share_to,
                'note': note,
                'show_dlp_veto_msg': show_dlp_veto_msg,
            })
            return func(request, fileshare, *args, **kwargs)

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
                file_shared_link_decrypted.send(sender=None, fileshare=fileshare,
                                                request=request, success=True)
                set_share_link_access(request, token)
                clear_share_link_decrypt_failed_attempts(ip)

                return func(request, fileshare, *args, **kwargs)
            else:
                file_shared_link_decrypted.send(sender=None, fileshare=fileshare,
                                                request=request, success=False)

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
