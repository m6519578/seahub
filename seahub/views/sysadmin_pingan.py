# -*- coding: utf-8 -*-
"""
Extra sysadmin functions for Zhong Guo Ping An.
"""
from collections import namedtuple
import logging
import json
import os

from django.core.urlresolvers import reverse
from django.contrib import messages
from django.http import HttpResponse, HttpResponseRedirect, Http404
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.template.defaultfilters import filesizeformat
from django.template.loader import render_to_string
from django.utils import translation
from django.utils.translation import ugettext as _

from seahub.base.accounts import User
from seahub.base.decorators import sys_staff_required
from seahub.base.templatetags.seahub_tags import email2nickname
from seahub.auth.decorators import login_required, login_required_ajax
from seahub.utils import gen_shared_upload_link, is_valid_email
from seahub.utils.ms_excel import write_xls
from seahub.share.models import FileShare, UploadLinkShare, \
    UploadLinkShareUploads, FileShareDownloads, FileShareExtraInfo, \
    FileShareReviserMap, FileShareVerifyIgnore, ApprovalChain, \
    approval_chain_str2list, approval_chain_list2str, FileShareApprovalStatus,\
    get_chain_step_sibling_type
from seahub.share.constants import STATUS_VERIFING, STATUS_PASS, STATUS_VETO
from seahub.settings import SITE_ROOT

logger = logging.getLogger(__name__)


@login_required
@sys_staff_required
def sys_reviser_admin(request):
    """List department approval chain.
    """
    # 1. get department list, e.g. [u'dept1', u'dept2', u'dept3']
    search_filter = request.GET.get('filter', '')
    if search_filter:
        qs = ApprovalChain.objects.filter(department__contains=search_filter
        ).values_list('department', flat=True).distinct()
    else:
        qs = ApprovalChain.objects.values_list('department',
                                               flat=True).distinct()

    # Make sure page request is an int. If not, deliver first page.
    try:
        current_page = int(request.GET.get('page', '1'))
        per_page = int(request.GET.get('per_page', '25'))
    except ValueError:
        current_page = 1
        per_page = 25

    offset = per_page * (current_page - 1)
    dept_plus_one = qs[offset:offset + per_page + 1]
    if len(dept_plus_one) == per_page + 1:
        page_next = True
    else:
        page_next = False

    # 2. get all records in those department list
    ret = []
    for dept in dept_plus_one[:per_page]:
        chain_obj = namedtuple('ChainObj', ['department', 'chain', 'chain_raw'])
        chain = ApprovalChain.objects.get_by_department(dept)
        chain_str = approval_chain_list2str(chain)
        chain_raw = approval_chain_list2str(chain, with_nickname=False)
        ret.append(chain_obj(department=dept, chain=chain_str,
                             chain_raw=chain_raw))

    return render_to_response(
        'sysadmin/sys_reviseradmin.html', {
            'chain_list': ret,
            'current_page': current_page,
            'prev_page': current_page - 1,
            'next_page': current_page + 1,
            'per_page': per_page,
            'page_next': page_next,
        }, context_instance=RequestContext(request))

@login_required
@sys_staff_required
def sys_reviser_admin_user_map(request):
    """List all reviser user maps.
    """
    search_filter = request.GET.get('filter', '')
    if search_filter:
        qs = FileShareReviserMap.objects.filter(
            username__contains=search_filter)
    else:
        qs = FileShareReviserMap.objects.all()

    # Make sure page request is an int. If not, deliver first page.
    try:
        current_page = int(request.GET.get('page', '1'))
        per_page = int(request.GET.get('per_page', '100'))
    except ValueError:
        current_page = 1
        per_page = 100

    offset = per_page * (current_page - 1)
    r_map_plus_one = qs[offset:offset + per_page + 1]
    if len(r_map_plus_one) == per_page + 1:
        page_next = True
    else:
        page_next = False

    return render_to_response(
        'sysadmin/sys_reviseradmin_user_map.html', {
            'r_map': r_map_plus_one[:per_page],
            'current_page': current_page,
            'prev_page': current_page - 1,
            'next_page': current_page + 1,
            'per_page': per_page,
            'page_next': page_next,
        }, context_instance=RequestContext(request))

@login_required
@sys_staff_required
def sys_reviser_admin_ignore(request):
    """List all ignored users.
    """
    search_filter = request.GET.get('filter', '')
    if search_filter:
        ignores = FileShareVerifyIgnore.objects.filter(
            username__contains=search_filter)
    else:
        ignores = FileShareVerifyIgnore.objects.all()

    return render_to_response(
        'sysadmin/sys_reviseradmin_ignore.html', {
            'ignores': ignores,
        }, context_instance=RequestContext(request))

@login_required_ajax
def reviser_add(request):
    """Add reviser"""

    if not request.user.is_staff or request.method != 'POST':
        raise Http404

    result = {}
    content_type = 'application/json; charset=utf-8'

    department_name = request.POST.get('department_name', '').strip()
    if not department_name:
        result['error'] = _(u'Invalid department')
        return HttpResponse(json.dumps(result), status=400, content_type=content_type)

    # if len(ApprovalChain.objects.filter(department=department_name)) > 0:
    #     result['error'] = '部门：%s 已存在'
    #     return HttpResponse(json.dumps(result), status=400, content_type=content_type)

    # remove duplicated records
    ApprovalChain.objects.filter(department=department_name).delete()

    chain = request.POST.get('chain', '').strip()
    if not chain:
        result['error'] = 'Chain empty'
        return HttpResponse(json.dumps(result), status=400, content_type=content_type)

    chain_list = approval_chain_str2list(chain)
    for e in chain_list:
        if isinstance(e, basestring):
            if not is_valid_email(e):
                result['error'] = 'Invalid email: %s' % e
                return HttpResponse(json.dumps(result), status=400, content_type=content_type)
            try:
                u = User.objects.get(email=e)
                if not u.is_active:
                    result['error'] = u'用户未激活: %s' % e
                    return HttpResponse(json.dumps(result), status=400, content_type=content_type)
            except User.DoesNotExist:
                result['error'] = u'用户不存在: %s' % e
                return HttpResponse(json.dumps(result), status=400, content_type=content_type)
        else:
            for x in e[1:]:
                if not is_valid_email(x):
                    result['error'] = 'Invalid email: %s' % x
                    return HttpResponse(json.dumps(result), status=400, content_type=content_type)
                try:
                    u = User.objects.get(email=x)
                    if not u.is_active:
                        result['error'] = u'用户未激活: %s' % e
                        return HttpResponse(json.dumps(result), status=400, content_type=content_type)
                except User.DoesNotExist:
                    result['error'] = u'用户不存在: %s' % x
                    return HttpResponse(json.dumps(result), status=400, content_type=content_type)

    ApprovalChain.objects.create_chain(department_name, chain_list)
    result['success'] = True
    return HttpResponse(json.dumps(result), content_type=content_type)

@login_required_ajax
def reviser_test(request):
    """Test reviser syntax"""

    if not request.user.is_staff or request.method != 'POST':
        raise Http404

    result = {}
    content_type = 'application/json; charset=utf-8'

    department_name = request.POST.get('department_name', '').strip()
    if not department_name:
        result['error'] = _(u'Invalid department')
        return HttpResponse(json.dumps(result), status=400, content_type=content_type)

    # if len(ApprovalChain.objects.filter(department=department_name)) > 0:
    #     result['error'] = '部门：%s 已存在' % (department_name)
    #     return HttpResponse(json.dumps(result), status=400, content_type=content_type)

    chain = request.POST.get('chain', '').strip()
    if not chain:
        result['error'] = 'Chain empty'
        return HttpResponse(json.dumps(result), status=400, content_type=content_type)

    chain_list = approval_chain_str2list(chain)
    ret = []
    for e in chain_list:
        if isinstance(e, basestring):
            if not is_valid_email(e):
                result['error'] = 'Invalid email: %s' % e
                return HttpResponse(json.dumps(result), status=400, content_type=content_type)

            try:
                u = User.objects.get(email=e)
                if not u.is_active:
                    result['error'] = u'用户未激活: %s' % e
                    return HttpResponse(json.dumps(result), status=400, content_type=content_type)
            except User.DoesNotExist:
                result['error'] = u'用户不存在: %s' % e
                return HttpResponse(json.dumps(result), status=400, content_type=content_type)
            ret.append(u"(%s) %s 顺序审批" % (email2nickname(e), e))
        else:
            for x in e[1:]:
                if not is_valid_email(x):
                    result['error'] = 'Invalid email: %s' % x
                    return HttpResponse(json.dumps(result), status=400, content_type=content_type)
                try:
                    u = User.objects.get(email=x)
                    if not u.is_active:
                        result['error'] = u'用户未激活: %s' % e
                        return HttpResponse(json.dumps(result), status=400, content_type=content_type)
                except User.DoesNotExist:
                    result['error'] = u'用户不存在: %s' % x
                    return HttpResponse(json.dumps(result), status=400, content_type=content_type)

                ret.append(u"(%s) %s 协同审批" % (email2nickname(x), x))

    result['ret'] = '<br>'.join(ret)
    return HttpResponse(json.dumps(result), content_type=content_type)

@login_required_ajax
def reviser_map_add(request):
    """Add reviser map"""

    if not request.user.is_staff or request.method != 'POST':
        raise Http404

    result = {}
    content_type = 'application/json; charset=utf-8'

    user_email = request.POST.get('user_email', None)
    if not user_email:
        result['error'] = 'Invalid email'
        return HttpResponse(json.dumps(result), status=400,
                            content_type=content_type)

    reviser_email = request.POST.get('reviser_email', None)
    if not reviser_email or not is_valid_email(reviser_email):
        result['error'] = 'Invalid reviser email'
        return HttpResponse(json.dumps(result), status=400, content_type=content_type)

    reviser_name = request.POST.get('reviser_name', '')
    reviser_account = request.POST.get('reviser_account', '')

    try:
        fs_rm = FileShareReviserMap.objects.get(username=user_email)
        # update
        fs_rm.reviser_name = reviser_name
        fs_rm.reviser_account = reviser_account
        fs_rm.reviser_email = reviser_email
        fs_rm.save()
        result['success'] = True
        return HttpResponse(json.dumps(result), content_type=content_type)
    except FileShareReviserMap.DoesNotExist:
        pass

    # add
    FileShareReviserMap.objects.create(
        username=user_email, reviser_name=reviser_name,
        reviser_account=reviser_account, reviser_email=reviser_email)

    result['success'] = True
    return HttpResponse(json.dumps(result), content_type=content_type)

@login_required_ajax
def verify_ignore_add(request):
    """Add verify ignore user"""

    if not request.user.is_staff or request.method != 'POST':
        raise Http404

    result = {}
    content_type = 'application/json; charset=utf-8'

    user_email = request.POST.get('user_email', None)
    if not user_email:
        result['error'] = 'Invalid email'
        return HttpResponse(json.dumps(result), status=400,
                            content_type=content_type)

    if len(FileShareVerifyIgnore.objects.filter(username=user_email)) > 0:
        result['error'] = _('This user has already been added')
        return HttpResponse(json.dumps(result), status=400, content_type=content_type)

    FileShareVerifyIgnore.objects.create(username=user_email)

    result['success'] = True
    return HttpResponse(json.dumps(result), content_type=content_type)

@login_required
@sys_staff_required
def reviser_remove(request, dept):
    """Remove reviser"""
    referer = request.META.get('HTTP_REFERER', None)
    next = reverse('sys_reviser_admin') if referer is None else referer

    ApprovalChain.objects.filter(department=dept).delete()

    return HttpResponseRedirect(next)

@login_required
@sys_staff_required
def reviser_map_remove(request, reviser_info_id):
    """Remove reviser map"""
    referer = request.META.get('HTTP_REFERER', None)
    next = reverse('sys_reviser_admin_user_map') if referer is None else referer

    try:
        FileShareReviserMap.objects.get(id=reviser_info_id).delete()
        messages.success(request, _(u'Success'))
    except Exception as e:
        logger.error(e)
        messages.error(request, _(u'Failed'))

    return HttpResponseRedirect(next)

@login_required
@sys_staff_required
def verify_ignore_remove(request, pk):
    """Remove reviser map"""
    referer = request.META.get('HTTP_REFERER', None)
    next = reverse('sys_reviser_admin_ignore') if referer is None else referer

    try:
        FileShareVerifyIgnore.objects.get(pk=pk).delete()
        messages.success(request, _(u'Success'))
    except Exception as e:
        logger.error(e)
        messages.error(request, _(u'Failed'))

    return HttpResponseRedirect(next)

@login_required_ajax
@sys_staff_required
def ajax_get_upload_files_info(request):

    content_type = 'application/json; charset=utf-8'

    link_id = request.GET.get('upload_link_id', None)
    if not link_id:
        return HttpResponse(json.dumps({'error': _(u'Invalid Argument')}),
                            status=500, content_type=content_type)

    u_link_uploads = UploadLinkShareUploads.objects.filter(upload_link_id=link_id)
    ctx_dict = {"uploads": u_link_uploads, }
    html = render_to_string('share/upload_info.html', ctx_dict)

    return HttpResponse(json.dumps({'html': html}), content_type=content_type)

def prepare_download_links(download_links):
    fs_downloads = FileShareDownloads.objects.all()

    dl_dict = {}
    for ele in fs_downloads:
        try:
            share_link_id = ele.share_link.pk
        except FileShare.DoesNotExist:
            ele.delete()
            continue

        val = dl_dict.get(share_link_id)
        if val:
            val['dl_counts'] += 1
        else:
            dl_dict[share_link_id] = {
                'first_dl_time': ele.download_time,
                'dl_counts': 1,
            }

    for d_link in download_links:
        d_link.filename = d_link.get_name()
        dl_info = dl_dict.get(d_link.pk, None)
        if dl_info:
            d_link.first_dl_time = dl_info['first_dl_time']
            d_link.dl_cnt = dl_info['dl_counts']
        else:
            d_link.first_dl_time = None
            d_link.dl_cnt = 0
        d_link.is_expired = d_link.is_expired()
        d_link.shared_link = d_link.get_full_url()

    return download_links

def prepare_upload_links(upload_links):
    for u_link in upload_links:
        u_link.shared_link = gen_shared_upload_link(u_link.token)
        u_link.dirname = '/' if u_link.path == '/' else \
            os.path.basename(u_link.path.rstrip('/'))

    return upload_links

@login_required
@sys_staff_required
def sys_download_links_report_search(request):

    search_user = request.GET.get('name', None)
    if not search_user:
        referer = request.META.get('HTTP_REFERER', None)
        next = reverse('sys_download_links_report') if referer is None else referer
        return HttpResponseRedirect(next)

    search_user = search_user.strip()
    download_links = FileShare.objects.list_file_links().filter(username__iexact=search_user)
    download_links = prepare_download_links(download_links)
    return render_to_response(
        'sysadmin/sys_download_links_report_search.html', {
            'download_links': download_links,
            'name': search_user,
        }, context_instance=RequestContext(request))

@login_required
@sys_staff_required
def sys_upload_links_report_search(request):

    search_user = request.GET.get('name', None)
    if not search_user:
        referer = request.META.get('HTTP_REFERER', None)
        next = reverse('sys_upload_links_report') if referer is None else referer
        return HttpResponseRedirect(next)

    search_user = search_user.strip()
    upload_links = UploadLinkShare.objects.filter(username__iexact=search_user)
    upload_links = prepare_upload_links(upload_links)
    return render_to_response(
        'sysadmin/sys_upload_links_report_search.html', {
            'upload_links': upload_links,
            'name': search_user,
        }, context_instance=RequestContext(request))

@login_required
@sys_staff_required
def sys_download_links_report(request):

    try:
        current_page = int(request.GET.get('page', '1'))
        per_page = int(request.GET.get('per_page', '25'))
    except ValueError:
        current_page = 1
        per_page = 25

    start = per_page * (current_page - 1)
    end = per_page * (current_page - 1) + per_page + 1
    links = FileShare.objects.list_file_links().order_by('-ctime')[start: end]

    if len(links) == per_page + 1:
        page_next = True
    else:
        page_next = False

    download_links = links[:per_page]
    download_links = prepare_download_links(download_links)

    result_dict = {}
    template_name = 'sysadmin/sys_download_links_report.html'
    result_dict['download_links'] = download_links
    result_dict['current_page'] = current_page
    result_dict['prev_page'] = current_page - 1
    result_dict['next_page'] = current_page + 1
    result_dict['per_page'] = per_page
    result_dict['page_next'] = page_next

    return render_to_response(template_name, result_dict,
                              context_instance=RequestContext(request))

@login_required
@sys_staff_required
def sys_upload_links_report(request):

    try:
        current_page = int(request.GET.get('page', '1'))
        per_page = int(request.GET.get('per_page', '25'))
    except ValueError:
        current_page = 1
        per_page = 25

    start = per_page * (current_page - 1)
    end = per_page * (current_page - 1) + per_page + 1
    links = UploadLinkShare.objects.all().order_by('-ctime')[start: end]

    if len(links) == per_page + 1:
        page_next = True
    else:
        page_next = False

    upload_links = links[:per_page]
    upload_links = prepare_upload_links(upload_links)

    result_dict = {}
    template_name = 'sysadmin/sys_upload_links_report.html'
    result_dict['upload_links'] = upload_links
    result_dict['current_page'] = current_page
    result_dict['prev_page'] = current_page - 1
    result_dict['next_page'] = current_page + 1
    result_dict['per_page'] = per_page
    result_dict['page_next'] = page_next

    return render_to_response(template_name, result_dict,
                              context_instance=RequestContext(request))

def download_links_excel_report(download_links):
    head = [
        _("Name"),
        _("From"),
        u"发送对象",
        _("Status"),
        _("Created at"),
        _("First Download Time"),
        _("Downloads"),
        _("Expiration"),
        _("Link"),
        _("DLP Status"),
        _("Time"),

        _("Email"),
        _("Status"),
        _("Time"),
    ]

    data_list = []

    download_links = prepare_download_links(download_links)
    status_dict = {
        STATUS_VERIFING: _('verifing'),
        STATUS_PASS: _('pass'),
        STATUS_VETO: _('veto')
    }
    for d_link in download_links:
        app_status = FileShareApprovalStatus.objects.get_chain_status_by_share_link(d_link)
        if not app_status:
            continue

        fs_info = FileShareExtraInfo.objects.filter(share_link=d_link)
        if len(fs_info) == 0:
            receivers = ''
        else:
            receivers = ','.join([x.sent_to for x in fs_info])

        # prepare excel data
        row = [d_link.filename, d_link.username, receivers,
               d_link.get_short_status_str(),
               d_link.ctime.strftime('%Y-%m-%d'),
               d_link.first_dl_time.strftime('%Y-%m-%d') if d_link.first_dl_time else '--',
               d_link.dl_cnt,
               d_link.expire_date.strftime('%Y-%m-%d') if d_link.expire_date else '--',
               d_link.shared_link,
        ]

        # 1. get DLP verify status
        DLP_status = '--'
        DLP_vtime = '--'
        DLP_status = status_dict.get(app_status[0].status, '')
        if app_status[0].vtime:
            DLP_vtime = app_status[0].vtime.strftime('%Y-%m-%d')

        row.append(DLP_status)
        row.append(DLP_vtime)

        # 2. get people verify status
        for ele in app_status[1:]:
            people_email = '--'
            people_status = '--'
            people_vtime = '--'

            if get_chain_step_sibling_type(ele):
                for x in ele[1:]:
                    people_email = x.email
                    people_status = status_dict.get(x.status, '')
                    if x.vtime:
                        people_vtime = x.vtime.strftime('%Y-%m-%d')

                    row.append(people_email)
                    row.append(people_status)
                    row.append(people_vtime)
            else:
                people_email = ele.email
                people_status = status_dict.get(ele.status, '')
                if ele.vtime:
                    people_vtime = ele.vtime.strftime('%Y-%m-%d')

                row.append(people_email)
                row.append(people_status)
                row.append(people_vtime)

        data_list.append(row)
    return (head, data_list)

@login_required
@sys_staff_required
def sys_links_report_export_excel(request):
    """export links to excel.
    """
    next = request.META.get('HTTP_REFERER', None)
    # save current language
    cur_language = translation.get_language()
    translation.activate('zh-cn')

    search_user = request.GET.get('search_user', None)
    link_type = request.GET.get('type', 'download')
    if link_type == 'download':
        if not next:
            next = reverse(sys_download_links_report)

        if search_user:
            download_links = FileShare.objects.filter(username__contains=search_user).filter(s_type='f')
        else:
            download_links = FileShare.objects.filter(s_type='f')

        head, data_list = download_links_excel_report(download_links)
        wb = write_xls(_('download links'), head, data_list)
        response = HttpResponse(content_type='application/ms-excel')
        response['Content-Disposition'] = 'attachment; filename=download-links.xls'

    elif link_type == 'upload':
        if not next:
            next = reverse(sys_upload_links_report)

        head = [
            _("Name"),
            _("From"),
            _("Link"),
            _("Upload File Name"),
            _("Upload File Size"),
            _("Upload Time"),
            _("Upload IP"),
        ]

        data_list = []
        if search_user:
            upload_links = UploadLinkShare.objects.filter(username__contains=search_user)
        else:
            upload_links = UploadLinkShare.objects.all()

        upload_links = prepare_upload_links(upload_links)
        for u_link in upload_links:

            u_link_uploads = UploadLinkShareUploads.objects.filter(upload_link=u_link)
            if u_link_uploads:
                for upload in u_link_uploads:
                    row = [
                        u_link.dirname,
                        u_link.username,
                        u_link.shared_link,
                        upload.file_name,
                        filesizeformat(upload.file_size),
                        upload.upload_time.strftime('%Y-%m-%d') if upload.upload_time else '--',
                        upload.upload_ip,
                    ]
                    data_list.append(row)
            else:
                row = [
                    u_link.dirname,
                    u_link.username,
                    u_link.shared_link,
                    '--',
                    '--',
                    '--',
                    '--',
                ]
                data_list.append(row)

        wb = write_xls(_('upload links'), head, data_list)
        response = HttpResponse(content_type='application/ms-excel')
        response['Content-Disposition'] = 'attachment; filename=upload-links.xls'

    else:
        messages.error(request, _(u'Failed to export excel, invalid argument.'))
        return HttpResponseRedirect(next)

    if not wb:
        next = request.META.get('HTTP_REFERER', None)
        if not next:
            next = SITE_ROOT

        messages.error(request, _(u'Failed to export excel'))
        return HttpResponseRedirect(next)

    wb.save(response)

    # restore current language
    translation.activate(cur_language)

    return response
