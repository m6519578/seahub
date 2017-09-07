# -*- coding: utf-8 -*-
"""
PingAn Group related views functions.
"""
import logging
import json
import os

from django.core.cache import cache
from django.core.urlresolvers import reverse
from django.http import HttpResponse, HttpResponseRedirect, Http404
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.utils import timezone
from django.utils.encoding import smart_text
from django.utils.translation import ugettext as _
from django.contrib import messages

from seahub.auth.decorators import login_required, login_required_ajax
from seahub.base.decorators import user_mods_check, require_POST
from seahub.base.templatetags.seahub_tags import email2nickname
from seahub.share.constants import STATUS_VERIFING, STATUS_PASS, STATUS_VETO
from seahub.share.models import (FileShare, FileShareDownloads,
                                 FileShareReceiver,
                                 FileShareExtraInfo, FileShareApprovalStatus,
                                 get_chain_step_emails, get_chain_step_status,
                                 get_chain_next_step)
from seahub.share.share_link_checking import (
    email_reviser, email_verify_result)
from seahub.share.signals import file_shared_link_verify
from seahub.utils import gen_token, send_html_email
from seahub.utils.ms_excel import write_xls
from seahub.settings import SITE_ROOT

# Get an instance of a logger
logger = logging.getLogger(__name__)


def get_verify_link_by_user(username):
    verifing_links, verified_links = [], []
    ret = FileShareApprovalStatus.objects.get_by_email(username)
    for e in ret:
        ele = e.share_link
        ele.filename = os.path.basename(ele.path)
        ele.shared_link = ele.get_full_url()
        ele.first_dl_time = FileShareDownloads.objects.get_first_download_time(ele)

        if e.status == STATUS_VERIFING:
            if not e.share_link.is_verifing():  # share link is not verified by me
                e.delete()
                continue
            else:
                verifing_links.append(ele)
        else:
            verified_links.append(ele)
    return verifing_links, verified_links

@login_required
@user_mods_check
def list_file_share_verify(request):
    """List file links that need verify.
    列出审批员“待审批的外链”／“已审批的外链”：

1. 从审批链（部门－部门长－稽核）里得到当前用户能审批的部门列表；--> dept_list
2. 得到所有属于(dept_list)的成员（注意：精确到部门即可，基础架构部项目组和基础架构步系统组同属一个审批链）；--> users
3. 得到所有 users 的外链；--> fileshares
4. 遍历每条外链（fileshare）,
    如果外链状态为审核通过／否决，则加入“已审批”列表；（待审核的外链，我有可能已经审核完毕，等待其他人审核）
    否则得到该外链的审批人员的邮箱列表，
      如果当前用户属于这个列表，并且“通过”或“否决”该外链，则加入“已审批”列表；
      否则，加入“待审批”列表。
    """
    username = request.user.username
    verifing_links, verified_links = get_verify_link_by_user(username)

    cmp_func = lambda x, y: cmp(y.ctime, x.ctime)
    verifing_links = sorted(verifing_links, cmp=cmp_func)
    verified_links = sorted(verified_links, cmp=cmp_func)

    return render_to_response('share/links_verify.html', {
            "verifing_links": verifing_links,
            "verified_links": verified_links,
    }, context_instance=RequestContext(request))

@login_required
def remove_file_share_verify(request, sid):
    username = request.user.username

    try:
        fs = FileShare.objects.get(pk=sid)
    except FileShare.DoesNotExist:
        raise Http404

    fs_s = FileShareApprovalStatus.objects.filter(share_link=fs, email=username)
    for ele in fs_s:
        if ele.status != STATUS_VERIFING:
            continue
        ele.delete()

    messages.success(request, _('Success'))
    return HttpResponseRedirect(reverse('list_file_share_verify'))

@login_required
def export_verified_links(request):
    """export user verified links to excel.
    """
    head = [
        _("Name"),
        _("From"),
        _("Pass/Veto"),
        _("Time"),
        _("DLP"),
        _("Time"),
        _("Create Time"),
        _("Expiration"),
        _("First Download Time"),
        _("Visits"),
        _("Link"),
    ]
    data_list = []
    username = request.user.username
    verifing_links, verified_links = get_verify_link_by_user(username)

    for link in verified_links:
        app_s = FileShareApprovalStatus.objects.get(share_link=link, email=username)

        pass_or_veto = '--'
        if app_s.status == STATUS_PASS:
            pass_or_veto = _('Approved')
        if app_s.status == STATUS_VETO:
            pass_or_veto = _('Rejected')

        try:
            verify_time = app_s.vtime.strftime('%Y-%m-%d')
        except AttributeError:
            verify_time = '--'

        dlp_s = FileShareApprovalStatus.objects.get_dlp_status_by_share_link(link)
        if dlp_s.status == STATUS_PASS:
            DLP_status = _('Approved')
        elif dlp_s.status == STATUS_VETO:
            DLP_status = _('Rejected')
        else:
            DLP_status = _('Verifing')

        try:
            DLP_vtime = dlp_s.vtime.strftime('%Y-%m-%d')
        except AttributeError:
            DLP_vtime = '--'

        first_dl_time = FileShareDownloads.objects.get_first_download_time(link)

        row = [
            link.filename,
            link.username,
            pass_or_veto,
            verify_time,
            DLP_status,
            DLP_vtime,
            link.ctime.strftime('%Y-%m-%d') if link.ctime else '--',
            link.expire_date.strftime('%Y-%m-%d') if link.expire_date else '--',
            first_dl_time.strftime('%Y-%m-%d') if first_dl_time else '--',
            link.view_cnt,
            link.shared_link,
        ]
        data_list.append(row)

    wb = write_xls(_('verified links'), head, data_list)

    if not wb:
        next = request.META.get('HTTP_REFERER', None)
        if not next:
            next = SITE_ROOT

        messages.error(request, _(u'Failed to export excel'))
        return HttpResponseRedirect(next)

    response = HttpResponse(content_type='application/ms-excel')
    response['Content-Disposition'] = 'attachment; filename=verified-links.xls'
    wb.save(response)
    return response

@login_required_ajax
@require_POST
def ajax_change_dl_link_status(request):
    """Approve or veto a shared link.

    Arguments:
    - `request`:
    """
    content_type = 'application/json; charset=utf-8'

    token = request.POST.get('t', '')
    if not token:
        return HttpResponse({}, status=400, content_type=content_type)

    try:
        status = int(request.POST.get('s', ''))
    except ValueError:
        return HttpResponse({}, status=400, content_type=content_type)

    if status not in (STATUS_PASS, STATUS_VETO):
        return HttpResponse({}, status=400, content_type=content_type)

    try:
        fileshare = FileShare.objects.get(token=token)
    except FileShare.DoesNotExist:
        return HttpResponse({}, status=400, content_type=content_type)

    username = request.user.username
    chain = fileshare.get_approval_chain(flat=True)
    if username not in chain:
        return HttpResponse({}, status=403, content_type=content_type)

    # check whether it is approved/veto by me or others siblings
    chain_status = FileShareApprovalStatus.objects.get_chain_status_by_share_link(fileshare)
    for ele in chain_status:
        emails = get_chain_step_emails(ele)
        if username not in emails:
            continue

        # user is in current step ...
        if get_chain_step_status(ele) != STATUS_VERIFING:
            # and current step is already pass/veto
            return HttpResponse({}, status=409, content_type=content_type)

    # change status
    msg = request.POST.get('msg', None)
    try:
        FileShareApprovalStatus.objects.set_status(fileshare, status, username, msg=msg)
    except ValueError:
        return HttpResponse({}, status=400, content_type=content_type)

    # reset expiration time starts from now if pass verify
    # also need to reset downloads counts
    if fileshare.pass_verify():
        new_expire_date = timezone.now() + (fileshare.expire_date - fileshare.ctime)
        fileshare.expire_date = new_expire_date
        fileshare.save()

        FileShareDownloads.objects.filter(share_link=fileshare).delete()

        # send email to share link receivers
        try:
            fileshare.email_receivers()
        except Exception as e:
            logger.error(e)

    # get emails in next step
    next_revisers = []
    chain_status_list = FileShareApprovalStatus.objects.get_chain_status_by_share_link(fileshare)
    next_step = get_chain_next_step(chain_status_list, username)
    if next_step is not None:
        next_revisers = get_chain_step_emails(next_step)

    # email next reviser in revisers chain if current reviser approved
    if status == STATUS_PASS and len(next_revisers) > 0:
        for e in next_revisers:
            # add default approval status
            FileShareApprovalStatus.objects.set_status(
                fileshare, status=STATUS_VERIFING, username=e)

            # send notice first
            file_shared_link_verify.send(sender=None,
                                         from_user=fileshare.username,
                                         to_user=e,
                                         token=fileshare.token)
            email_reviser(fileshare, e)

    # email verify result to shared link owner
    email_verify_result(fileshare, fileshare.username,
                        source="%s (%s)" % (smart_text(email2nickname(username)), username),
                        result_code=str(status))

    return HttpResponse({}, status=200, content_type=content_type)

def ajax_get_link_verify_code(request):
    """Get verify code in decrypt download share link page.
    """
    content_type = 'application/json; charset=utf-8'

    token = request.POST.get('token')
    email = request.POST.get('email')

    fs = FileShare.objects.get_valid_file_link_by_token(token)
    if fs is None:
        return HttpResponse(json.dumps({
            'error': _('Share link is not found')
        }), status=400, content_type=content_type)

    if len(list(FileShareReceiver.objects.filter(share_link=fs, email=email))) == 0:
        return HttpResponse(json.dumps({
            'error': _('This email is not in the shared list')
        }), status=403, content_type=content_type)

    cache_key = 'share_link_verify_code_%s' % token
    timeout = 60 * 60           # one hour

    # get code from cache
    code = cache.get(cache_key)
    if not code:
        # or generate new code
        code = gen_token(max_length=6)
        cache.set(cache_key, code, timeout)

    # send code to user via email
    subject = _("Verify code for link: %s") % fs.get_full_url()
    c = {
        'code': code,
    }
    try:
        send_html_email(subject, 'share/verify_code_email.html',
                        c, None, [email])
        return HttpResponse(json.dumps(code), status=200,
                            content_type=content_type)
    except Exception as e:
        logger.error('Failed to send verify code via email to %s')
        logger.error(e)
        return HttpResponse(json.dumps({
            "error": _("Failed to send verify code, please try again later.")
        }), status=500, content_type=content_type)

@login_required_ajax
@require_POST
def ajax_remind_revisers(request):
    content_type = 'application/json; charset=utf-8'

    token = request.POST.get('token', '')
    if not token:
        return HttpResponse({}, status=400, content_type=content_type)

    fileshare = FileShare.objects.get(token=token)
    if not fileshare or not fileshare.is_verifing():
        return HttpResponse({}, status=400, content_type=content_type)

    if fileshare.username != request.user.username:
        return HttpResponse({}, status=403, content_type=content_type)

    chain_status_list = FileShareApprovalStatus.objects.get_chain_status_by_share_link(fileshare)
    send_to = []
    for step in chain_status_list[1:]:
        if get_chain_step_status(step) == STATUS_VERIFING:
            send_to = get_chain_step_emails(step)
            break

    for x in send_to:
        # add default approval status if possible
        FileShareApprovalStatus.objects.set_status(
            fileshare, status=STATUS_VERIFING, username=x)

        # send notice first
        file_shared_link_verify.send(sender=None,
                                     from_user=fileshare.username,
                                     to_user=x,
                                     token=fileshare.token)

        email_reviser(fileshare, x)
        logger.info('An remind email sent to %s triggered by user %s' % (
            x, fileshare.username))
    return HttpResponse(json.dumps({'sent': send_to}),
                        status=200, content_type=content_type)

@login_required
def ajax_get_link_receivers(request):
    """Get receiver emails of a shared link.
    """
    content_type = 'application/json; charset=utf-8'
    token = request.GET.get('token')

    try:
        fs = FileShare.objects.get(token=token)
    except FileShare.DoesNotExist:
        return HttpResponse(json.dumps({
            'error': _('Share link is not found')
        }), status=400, content_type=content_type)

    if fs.username != request.user.username:
        return HttpResponse({}, status=403, content_type=content_type)

    fs_info = FileShareExtraInfo.objects.filter(share_link=fs)
    if len(fs_info) == 0:
        return HttpResponse(json.dumps({
            'error': 'Sent to emails are not found'
        }), status=400, content_type=content_type)

    sent_to = [x.sent_to for x in fs_info]
    return HttpResponse(json.dumps({'receivers': sent_to}),
                        status=200, content_type=content_type)

@login_required
def ajax_email_link_receivers(request):
    """Send email to link receivers
    """
    content_type = 'application/json; charset=utf-8'
    token = request.GET.get('token')

    try:
        fs = FileShare.objects.get(token=token)
    except FileShare.DoesNotExist:
        return HttpResponse(json.dumps({
            'error': _('Share link is not found')
        }), status=400, content_type=content_type)

    if fs.is_expired():
        return HttpResponse(json.dumps({
            'error': u"发送失败：该外链已过期",
        }), status=400, content_type=content_type)

    if fs.username != request.user.username:
        return HttpResponse({}, status=403, content_type=content_type)

    fs.email_receivers()
    return HttpResponse(json.dumps({'success': True}),
                        status=200, content_type=content_type)

@login_required
def ajax_get_link_status(request):
    """Get link status and other info.
    """
    content_type = 'application/json; charset=utf-8'
    token = request.GET.get('token')

    try:
        fs = FileShare.objects.get(token=token)
    except FileShare.DoesNotExist:
        return HttpResponse(json.dumps({
            'error': _('Share link is not found')
        }), status=400, content_type=content_type)

    if not request.user.is_staff and fs.username != request.user.username:
        return HttpResponse({}, status=403, content_type=content_type)

    fs_v = fs.get_verbose_status()
    if not fs_v:
        return HttpResponse(json.dumps({
            'error': _('No revisers found. Please contact system admin.')
        }), status=400, content_type=content_type)

    ret = {}
    s_list = []
    for s, v in fs_v:
        s_list.append(v)
    ret['status'] = s_list

    fs_info = FileShareExtraInfo.objects.filter(share_link=fs)
    if len(fs_info) == 0:
        receivers = []
    else:
        receivers = [x.sent_to for x in fs_info]
    ret['receivers'] = receivers

    ret['pass_verify'] = fs.pass_verify()
    ret['sent_at'] = fs.get_pass_time()

    decoded_pwd = fs.get_decoded_password(fs.password)
    if decoded_pwd:
        ret['password'] = decoded_pwd
    else:
        ret['password'] = _('Unsupported password format, please regenerate link if you want to show password.')

    return HttpResponse(json.dumps(ret),
                        status=200, content_type=content_type)
