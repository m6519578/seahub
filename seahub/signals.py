import django.dispatch

# Use org_id = -1 if it's not an org repo
repo_created = django.dispatch.Signal(providing_args=["org_id", "creator", "repo_id", "repo_name"])
repo_deleted = django.dispatch.Signal(providing_args=["org_id", "usernames", "repo_owner", "repo_id", "repo_name"])
upload_file_successful = django.dispatch.Signal(providing_args=["repo_id", "file_path", "owner"])

######################### Start PingAn Group related ########################
file_deleted = django.dispatch.Signal(providing_args=["org_id", "parent_dir", "file_name", "username"])
file_edited = django.dispatch.Signal(providing_args=["org_id", "parent_dir", "file_name", "username"])
######################### End PingAn Group related ##########################
