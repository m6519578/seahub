from django.core.urlresolvers import reverse

from seahub.share.models import (FileShare, FileShareVerify,
                                 FileShareReviserChain, FileShareReviserMap)
from seahub.profile.models import Profile, DetailedProfile


class SetupRevisersMixin(object):
    def setup_revisers(self):
        department = 'dept_A'
        FileShareReviserChain.objects.add_file_share_reviser(
            department,
            # line manager
            self.user.username, self.user.username, self.user.username,
            # department head
            self.user.username, self.user.username, self.user.username,
            # comanager head
            self.admin.username, self.admin.username, self.admin.username,
            # compliance owner
            self.admin.username, self.admin.username, self.admin.username,
        )

        Profile.objects.add_or_update(self.user.username, '', '')
        DetailedProfile.objects.add_detailed_profile(self.user.username, department, '')

        Profile.objects.add_or_update(self.admin.username, '', '')
        DetailedProfile.objects.add_detailed_profile(self.admin.username, department, '')

    def setup_reviser_map(self):
        FileShareReviserMap.objects.create(
            username=self.user.username, reviser_name='', reviser_account='',
            reviser_email=self.user.username)


class AddDownloadLinkMixin(object):
    def add_shared_file_link(self):
        assert len(FileShare.objects.all()) == 0
        assert len(FileShareVerify.objects.all()) == 0

        self.login_as(self.user)
        data = {
            'repo_id': self.user_repo_id,
            'p': self.user_file_path,
            'type': 'f',
            'use_passwd': '1',
            'passwd': '12345678',
            'expire_days': 3,
        }
        url = reverse('ajax_get_download_link')
        self.client.post(url, data, HTTP_X_REQUESTED_WITH='XMLHttpRequest')

        assert len(FileShare.objects.all()) == 1
        assert len(FileShareVerify.objects.all()) == 1

        self.logout()
        return FileShare.objects.all()[0]
