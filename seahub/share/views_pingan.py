# -*- coding: utf-8 -*-
"""
PingAn Group related views functions.
"""
import logging
import json
import os

from django.core.cache import cache
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.utils import timezone
from django.utils.translation import ugettext as _
from django.contrib import messages

from seahub.auth.decorators import login_required, login_required_ajax
from seahub.base.decorators import user_mods_check, require_POST
from seahub.base.templatetags.seahub_tags import email2nickname
from seahub.profile.models import DetailedProfile
from seahub.share.constants import STATUS_VERIFING, STATUS_PASS, STATUS_VETO
from seahub.share.models import (FileShare, FileShareReviserInfo,
                                 FileShareVerify, FileShareDownloads,
                                 FileShareReceiver, FileShareReviserMap)
from seahub.share.share_link_checking import (
    email_reviser, email_verify_result, get_reviser_emails_by_user)
from seahub.utils import gen_token, send_html_email
from seahub.utils.ms_excel import write_xls
from seahub.settings import SITE_ROOT

# Get an instance of a logger
logger = logging.getLogger(__name__)

def list_share_links_by_reviser(username):
    """List all share links by reviser name.
    """
    users = []

    # 1. get users from revisermap
    for e in FileShareReviserMap.objects.filter(reviser_email=username):
        users.append(e.username)

    # 2. get department list according to reviser info table
    dept_list = []
    for e in FileShareReviserInfo.objects.all():
        if e.department_head_email == username or \
           e.comanager_head_email == username or \
           e.reviser1_email == username or e.reviser2_email == username:
            dept_list.append(e.department_name)

    if dept_list:
        # get all user list belong to those departments
        for dept in dept_list:
            for e in DetailedProfile.objects.filter(department__startswith=dept):
                users.append(e.user)

    users = list(set(users))
    # get share link belong to those users
    return FileShare.objects.filter(username__in=users).order_by('-ctime')[:100]

def get_verify_link_by_user(username):
    verifing_links = []
    verified_links = []

    fileshares = list_share_links_by_reviser(username)

    for fs in fileshares:
        fs.filename = os.path.basename(fs.path)
        fs.shared_link = fs.get_full_url()

        if fs.expire_date is not None and timezone.now() > fs.expire_date:
            fs.is_expired = True

        try:
            fs_verify = FileShareVerify.objects.get(share_link=fs)
        except FileShareVerify.DoesNotExist as e:
            logger.error(e)
            continue

        if not fs.is_verifing():
            verified_links.append(fs)
            continue            # continue to next shared link

        user_pass = False
        user_veto = False

        revisers = get_reviser_emails_by_user(fs.username)
        if username in revisers:
            if username == revisers[0]:
                if fs_verify.department_head_pass():
                    user_pass = True
                if fs_verify.department_head_veto():
                    user_veto = True

                if fs_verify.department_head_vtime:
                    fs.verify_time = fs_verify.department_head_vtime

            elif username == revisers[1]:
                if fs_verify.comanager_head_pass():
                    user_pass = True
                if fs_verify.comanager_head_veto():
                    user_veto = True

                if fs_verify.comanager_head_vtime:
                    fs.verify_time = fs_verify.comanager_head_vtime

            elif username == revisers[2] or username == revisers[3]:
                if fs_verify.revisers_pass():
                    user_pass = True
                if fs_verify.revisers_veto():
                    user_veto = True

                if fs_verify.reviser_vtime:
                    fs.verify_time = fs_verify.reviser_vtime

        if user_pass or user_veto:
            fs.user_pass = user_pass
            fs.user_veto = user_veto

            if fs_verify.DLP_status == STATUS_VERIFING:
                fs.DLP_status = _("verifing")
            elif fs_verify.DLP_status == STATUS_PASS:
                fs.DLP_status = _("pass")
            elif fs_verify.DLP_status == STATUS_VETO:
                fs.DLP_status = _("veto")

            if fs_verify.DLP_vtime:
                fs.DLP_vtime = fs_verify.DLP_vtime

            fs.first_dl_time = FileShareDownloads.objects.get_first_download_time(fs)

            verified_links.append(fs)
        else:
            verifing_links.append(fs)

    return verifing_links, verified_links


@login_required
@user_mods_check
def list_file_share_verify(request):
    """List file links that need verify.
    列出“待审批的外链”／“已审批的外链”：

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

    return render_to_response('share/links_verify.html', {
            "verifing_links": verifing_links,
            "verified_links": verified_links,
    }, context_instance=RequestContext(request))

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
    verifing_links, verified_links = get_verify_link_by_user(request.user.username)

    for link in verified_links:

        pass_or_veto = '--'

        if link.user_pass:
            pass_or_veto = _("Pass")
        elif link.user_veto:
            pass_or_veto = _("Veto")

        try:
            verify_time = link.verify_time.strftime('%Y-%m-%d')
        except AttributeError:
            verify_time = '--'

        try:
            DLP_vtime = link.DLP_vtime.strftime('%Y-%m-%d')
        except AttributeError:
            DLP_vtime = '--'

        first_dl_time = FileShareDownloads.objects.get_first_download_time(link)

        row = [
            link.filename,
            link.username,
            pass_or_veto,
            verify_time,
            link.DLP_status,
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

    if status not in (STATUS_VERIFING, STATUS_PASS, STATUS_VETO):
        return HttpResponse({}, status=400, content_type=content_type)

    try:
        fileshare = FileShare.objects.get(token=token)
    except FileShare.DoesNotExist:
        return HttpResponse({}, status=400, content_type=content_type)

    username = request.user.username
    revisers = get_reviser_emails_by_user(fileshare.username)
    if username not in revisers:
        return HttpResponse({}, status=403, content_type=content_type)

    try:
        FileShareVerify.objects.set_status(fileshare, status, username)
    except ValueError:
        return HttpResponse({}, status=400, content_type=content_type)

    if fileshare.pass_verify():
        # reset expiration time starts from now
        new_expire_date = timezone.now() + (fileshare.expire_date - fileshare.ctime)
        fileshare.expire_date = new_expire_date
        fileshare.save()

    # email verify result to shared link owner
    email_verify_result(fileshare, fileshare.username,
                        source="%s (%s)" % (email2nickname(username), username),
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

    revisers = [x for x in get_reviser_emails_by_user(fileshare.username) if x.strip()]
    remind_list = list(set(revisers))

    fs_v = FileShareVerify.objects.get(share_link=fileshare)
    if fs_v.department_head_status != STATUS_VERIFING:
        remind_list = [x for x in remind_list if x != revisers[0]]

    if fs_v.reviser_status != STATUS_VERIFING:
        remind_list = [x for x in remind_list if x != revisers[2]]
        remind_list = [x for x in remind_list if x != revisers[3]]

    for x in remind_list:
        email_reviser(fileshare, x)

    return HttpResponse(json.dumps({'sent': remind_list}),
                        status=200, content_type=content_type)
