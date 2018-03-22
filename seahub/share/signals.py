import django.dispatch

share_repo_to_user_successful = django.dispatch.Signal(providing_args=["from_user", "to_user", "repo"])
share_repo_to_group_successful = django.dispatch.Signal(providing_args=["from_user", "group_id", "repo"])

######################### Start PingAn Group related ########################
file_shared_link_created = django.dispatch.Signal(
    providing_args=["sent_to", "note"])
file_shared_link_verify = django.dispatch.Signal(
    providing_args=["from_user", "to_user", "token"])
file_shared_link_decrypted = django.dispatch.Signal(
    providing_args=["fileshare", "request", "success"])
######################### End PingAn Group related ##########################
