from django.conf.urls import patterns, url

from views import *

urlpatterns = patterns('',
    url(r'^$', list_shared_repos, name='share_admin'),
    url(r'^links/$', list_shared_links, name='list_shared_links'),
    url(r'^folders/$', list_priv_shared_folders, name='list_priv_shared_folders'),
    url(r'^add/$', share_repo, name='share_repo'),
    url(r'^remove/$', repo_remove_share, name='repo_remove_share'),
    url(r'^ajax/link/remove/$', ajax_remove_shared_link, name='ajax_remove_shared_link'),
    url(r'^link/send/$', send_shared_link, name='send_shared_link'),
    url(r'^link/save/$', save_shared_link, name='save_shared_link'),
    url(r'^ajax/upload_link/remove/$', ajax_remove_shared_upload_link, name='ajax_remove_shared_upload_link'),
    url(r'^upload_link/send/$', send_shared_upload_link, name='send_shared_upload_link'),
    url(r'^permission_admin/$', share_permission_admin, name='share_permission_admin'),
    url(r'^ajax/repo_remove_share/$', ajax_repo_remove_share, name='ajax_repo_remove_share'),
    url(r'^ajax/get-download-link/$', ajax_get_download_link, name='ajax_get_download_link'),
    url(r'^ajax/get-upload-link/$', ajax_get_upload_link, name='ajax_get_upload_link'),
    url(r'^ajax/private-share-dir/$', ajax_private_share_dir, name='ajax_private_share_dir'),
    url(r'^ajax/get-link-audit-code/$', ajax_get_link_audit_code, name='ajax_get_link_audit_code'),
)

######################### Start PingAn Group related ########################
from .views_pingan import *
urlpatterns += patterns(
    '',
    url(r'^links/verify/$', list_file_share_verify, name='list_file_share_verify'),
    url(r'^links/verify/remove/(?P<sid>\d+)/$', remove_file_share_verify, name='remove_file_share_verify'),
    url(r'^links/export-verified-links/$', export_verified_links, name='export_verified_links'),
    url(r'^ajax/change-download-link-status/$', ajax_change_dl_link_status, name='ajax_change_dl_link_status'),
    url(r'^ajax/get-link-verify-code/$', ajax_get_link_verify_code, name='ajax_get_link_verify_code'),
    url(r'^ajax/remind-revisers/$', ajax_remind_revisers, name='ajax_remind_revisers'),
    url(r'^ajax/get-link-receivers/$', ajax_get_link_receivers, name='ajax_get_link_receivers'),
    url(r'^ajax/email-link-receivers/$', ajax_email_link_receivers, name='ajax_email_link_receivers'),
    url(r'^ajax/get-link-status/$', ajax_get_link_status, name='ajax_get_link_status'),
)
######################### End PingAn Group related ##########################

