# -*- coding: utf-8 -*-
"""
Extra sysadmin functions for Zhong Guo Ping An.
"""
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
from django.utils.html import escape
from django.utils.translation import ugettext as _

from seahub.base.decorators import sys_staff_required
from seahub.auth.decorators import login_required, login_required_ajax
from seahub.utils import gen_shared_upload_link, is_valid_email
from seahub.utils.ms_excel import write_xls
from seahub.share.models import FileShare, UploadLinkShare, FileShareVerify, \
    FileShareReviserInfo, UploadLinkShareUploads, FileShareDownloads, \
    FileShareReviserMap, FileShareVerifyIgnore
from seahub.share.share_link_checking import get_reviser_info_by_user
from seahub.share.constants import STATUS_VERIFING, STATUS_PASS, STATUS_VETO
from seahub.settings import SITE_ROOT

logger = logging.getLogger(__name__)


@login_required
@sys_staff_required
def sys_reviser_admin(request):
    """List all reviser.
    """
    search_filter = request.GET.get('filter', '')
    if search_filter:
        qs = FileShareReviserInfo.objects.filter(
            department_name__contains=search_filter)
    else:
        qs = FileShareReviserInfo.objects.all()

    # Make sure page request is an int. If not, deliver first page.
    try:
        current_page = int(request.GET.get('page', '1'))
        per_page = int(request.GET.get('per_page', '100'))
    except ValueError:
        current_page = 1
        per_page = 100

    offset = per_page * (current_page - 1)
    revisers_plus_one = qs[offset:offset + per_page + 1]
    if len(revisers_plus_one) == per_page + 1:
        page_next = True
    else:
        page_next = False

    def format_td(name, account, email):
        l = []
        if name: l.append(name)
        if account: l.append(account)
        if email: l.append(email)
        return '<br />'.join(l)

    revisers = revisers_plus_one[:per_page]
    for r in revisers:
        r.department_head_info = format_td(
            r.department_head_name, r.department_head_account,
            r.department_head_email)

        r.comanager_head_info = format_td(
            r.comanager_head_name, r.comanager_head_account,
            r.comanager_head_email)

        r.reviser1_info = format_td(
            r.reviser1_name, r.reviser1_account,
            r.reviser1_email)

        r.reviser2_info = format_td(
            r.reviser2_name, r.reviser2_account,
            r.reviser2_email)

        r.comanager_head_info = format_td(
            r.comanager_head_name, r.comanager_head_account,
            r.comanager_head_email)

    return render_to_response(
        'sysadmin/sys_reviseradmin.html', {
            'revisers': revisers,
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

    department_name = request.POST.get('department_name', None)
    if not department_name:
        result['error'] = _(u'Invalid department')
        return HttpResponse(json.dumps(result), status=400, content_type=content_type)

    department_head_email = request.POST.get('department_head_email', None)
    if not department_head_email or not is_valid_email(department_head_email):
        result['error'] = _(u'Invalid department head email')
        return HttpResponse(json.dumps(result), status=400, content_type=content_type)

    department_head_name = request.POST.get('department_head_name', None)
    department_head_account = request.POST.get('department_head_account', None)

    reviser1_name = request.POST.get('reviser1_name', None)
    reviser1_account = request.POST.get('reviser1_account', None)
    reviser1_email = request.POST.get('reviser1_email', None)

    reviser2_name = request.POST.get('reviser2_name', None)
    reviser2_account = request.POST.get('reviser2_account', None)
    reviser2_email = request.POST.get('reviser2_email', None)

    try:
        fs_rinfo = FileShareReviserInfo.objects.get(department_name=department_name)
        fs_rinfo.department_head_name = department_head_name
        fs_rinfo.department_head_account = department_head_account
        fs_rinfo.department_head_email = department_head_email
        fs_rinfo.reviser1_name = reviser1_name
        fs_rinfo.reviser1_account = reviser1_account
        fs_rinfo.reviser1_email = reviser1_email
        fs_rinfo.reviser2_name = reviser2_name
        fs_rinfo.reviser2_account = reviser2_account
        fs_rinfo.reviser2_email = reviser2_email
        fs_rinfo.save()
        result['success'] = True
        return HttpResponse(json.dumps(result), content_type=content_type)
    except FileShareReviserInfo.DoesNotExist:
        pass

    # add new reviser info
    try:
        FileShareReviserInfo.objects.add_file_share_reviser(
            department_name,
            department_head_name, department_head_account, department_head_email,
            '', '', '', reviser1_name, reviser1_account, reviser1_email,
            reviser2_name, reviser2_account, reviser2_email)
        result['success'] = True
        return HttpResponse(json.dumps(result), content_type=content_type)
    except Exception as e:
        logger.error(e)
        result['error'] = _(u'Internal server error')
        return HttpResponse(json.dumps(result), status=500,
                            content_type=content_type)

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
def reviser_remove(request, reviser_info_id):
    """Remove reviser"""
    referer = request.META.get('HTTP_REFERER', None)
    next = reverse('sys_reviser_admin') if referer is None else referer

    try:
        FileShareReviserInfo.objects.get(id=reviser_info_id).delete()
        messages.success(request, _(u'Success'))
    except Exception as e:
        logger.error(e)
        messages.error(request, _(u'Failed'))

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
    for d_link in download_links:
        d_link.filename = d_link.get_name()
        d_link.shared_link = d_link.get_full_url()
        d_link.dl_cnt = FileShareDownloads.objects.filter(share_link=d_link).count()
        d_link.first_dl_time = FileShareDownloads.objects.get_first_download_time(share_link=d_link)
        d_link.is_expired = d_link.is_expired()

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
    links = FileShare.objects.list_file_links()[start: end]

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
    links = UploadLinkShare.objects.all()[start: end]

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

@login_required
@sys_staff_required
def sys_links_report_export_excel(request):
    """export links to excel.
    """
    next = request.META.get('HTTP_REFERER', None)

    search_user = request.GET.get('search_user', None)
    link_type = request.GET.get('type', 'download')
    if link_type == 'download':
        if not next:
            next = reverse(sys_download_links_report)

        head = [
            _("Name"),
            _("From"),
            _("DLP Status"),
            _("Time"),
            _("Department Head Email"),
            _("Department Head Status"),
            _("Time"),
            _("Reviser Email"),
            _("Reviser Status"),
            _("Time"),
            _("First Download Time"),
            _("Downloads"),
            _("Expiration"),
            _("Link"),
        ]

        data_list = []
        if search_user:
            download_links = FileShare.objects.filter(username__contains=search_user).filter(s_type='f')
        else:
            download_links = FileShare.objects.filter(s_type='f')

        download_links = prepare_download_links(download_links)
        for d_link in download_links:

            try:
                fs_verify = FileShareVerify.objects.get(share_link=d_link)
            except FileShareVerify.DoesNotExist as e:
                logger.error(e)
                continue

            reviser_info = get_reviser_info_by_user(d_link.username)
            if reviser_info is None:
                continue

            # get DLP verify status
            DLP_status = '--'
            DLP_vtime = '--'
            if fs_verify.DLP_status == STATUS_VERIFING:
                DLP_status = _('verifing')
            elif fs_verify.DLP_status == STATUS_PASS:
                DLP_status = _('pass')
            elif fs_verify.DLP_status == STATUS_VETO:
                DLP_status = _('veto')

            if fs_verify.DLP_vtime:
                DLP_vtime = fs_verify.DLP_vtime.strftime('%Y-%m-%d')

            # get department head verify status
            department_head_status = '--'
            department_head_vtime = '--'
            department_head_email = '--'
            if fs_verify.department_head_status == STATUS_VERIFING:
                department_head_status = _('verifing')
            elif fs_verify.department_head_status == STATUS_PASS:
                department_head_status = _('pass')
            elif fs_verify.department_head_status == STATUS_VETO:
                department_head_status = _('veto')

            if fs_verify.department_head_vtime:
                department_head_vtime = fs_verify.department_head_vtime.strftime('%Y-%m-%d')

            if reviser_info.department_head_email:
                department_head_email = reviser_info.department_head_email

            # get reviser verify status
            reviser_status = '--'
            reviser_vtime = '--'
            reviser_email = '--'
            if fs_verify.reviser_status == STATUS_VERIFING:
                reviser_status = _('verifing')
            elif fs_verify.reviser_status == STATUS_PASS:
                reviser_status = _('pass')
            elif fs_verify.reviser_status == STATUS_VETO:
                reviser_status = _('veto')

            if fs_verify.reviser_vtime:
                reviser_vtime = fs_verify.reviser_vtime.strftime('%Y-%m-%d')

            if reviser_info.reviser1_email or reviser_info.reviser2_email:
                reviser_email = reviser_info.reviser1_email + ',' + reviser_info.reviser2_email

            # prepare excel data
            row = [
                d_link.filename,
                d_link.username,
                DLP_status,
                DLP_vtime,
                department_head_email,
                department_head_status,
                department_head_vtime,
                reviser_email,
                reviser_status,
                reviser_vtime,
                d_link.first_dl_time.strftime('%Y-%m-%d') if d_link.first_dl_time else '--',
                d_link.dl_cnt,
                d_link.expire_date.strftime('%Y-%m-%d') if d_link.expire_date else '--',
                d_link.shared_link,
            ]

            data_list.append(row)

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
    return response
