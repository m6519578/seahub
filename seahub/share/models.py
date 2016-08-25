import datetime
import logging

from django.db import models
from django.utils import timezone
from django.utils.translation import ugettext as _

from seahub.base.fields import LowerCaseCharField
from seahub.utils import normalize_file_path, normalize_dir_path, gen_token,\
    get_service_url

######################### Start PingAn Group related ########################
import os
import posixpath
from seahub.share.constants import STATUS_VERIFING, STATUS_PASS, STATUS_VETO
from seahub.share.hashers import make_password, check_password, decode_password
from seahub.share.settings import ENABLE_FILESHARE_CHECK
######################### End PingAn Group related ##########################

# Get an instance of a logger
logger = logging.getLogger(__name__)


class AnonymousShare(models.Model):
    """
    Model used for sharing repo to unregistered email.
    """
    repo_owner = LowerCaseCharField(max_length=255)
    repo_id = models.CharField(max_length=36)
    anonymous_email = LowerCaseCharField(max_length=255)
    token = models.CharField(max_length=25, unique=True)

def _get_link_key(token, is_upload_link=False):
    return 'visited_ufs_' + token if is_upload_link else \
        'visited_fs_' + token

def set_share_link_access(request, token, is_upload_link=False):
    """Remember which shared download/upload link user can access without
    providing password.
    """
    if request.session:
        link_key = _get_link_key(token, is_upload_link)
        request.session[link_key] = True
    else:
        # should never reach here in normal case
        logger.warn('Failed to remember shared link password, request.session'
                    ' is None when set shared link access.')

def check_share_link_access(request, token, is_upload_link=False):
    """Check whether user can access shared download/upload link without
    providing password.
    """
    link_key = _get_link_key(token, is_upload_link)
    if request.session.get(link_key, False):
        return True
    else:
        return False

def check_share_link_common(request, sharelink, is_upload_link=False):
    """Check if user can view a share link
    """

    msg = ''
    if not sharelink.is_encrypted():
        return (True, msg)

    # if CAN access shared download/upload link without providing password
    # return True
    if check_share_link_access(request, sharelink.token, is_upload_link):
        return (True, msg)

    if request.method != 'POST':
        return (False, msg)

    password = request.POST.get('password', None)
    if not password:
        msg = _("Password can\'t be empty")
        return (False, msg)

    if check_password(password, sharelink.password):
        set_share_link_access(request, sharelink.token, is_upload_link)
        return (True, msg)
    else:
        msg = _("Please enter a correct password.")
        return (False, msg)

class FileShareManager(models.Manager):
    def _add_file_share(self, username, repo_id, path, s_type,
                        password=None, expire_date=None):
        if password is not None:
            password_enc = make_password(password)
        else:
            password_enc = None

        token = gen_token(max_length=10)
        fs = super(FileShareManager, self).create(
            username=username, repo_id=repo_id, path=path, token=token,
            s_type=s_type, password=password_enc, expire_date=expire_date)
        fs.save()
        return fs

    def _get_file_share_by_path(self, username, repo_id, path):
        fs = list(super(FileShareManager, self).filter(repo_id=repo_id).filter(
            username=username).filter(path=path))
        if len(fs) > 0:
            return fs[0]
        else:
            return None

    def _get_valid_file_share_by_token(self, token):
        """Return share link that exists and not expire, otherwise none.
        """
        try:
            fs = self.get(token=token)
        except self.model.DoesNotExist:
            return None

        if fs.expire_date is None:
            return fs
        else:
            if timezone.now() > fs.expire_date:
                return None
            else:
                return fs

    ########## public methods ##########
    def create_file_link(self, username, repo_id, path, password=None,
                         expire_date=None):
        """Create download link for file.
        """
        path = normalize_file_path(path)
        return self._add_file_share(username, repo_id, path, 'f', password,
                                    expire_date)

    def get_file_link_by_path(self, username, repo_id, path):
        path = normalize_file_path(path)
        return self._get_file_share_by_path(username, repo_id, path)

    def get_valid_file_link_by_token(self, token):
        return self._get_valid_file_share_by_token(token)

    def create_dir_link(self, username, repo_id, path, password=None,
                        expire_date=None):
        """Create download link for directory.
        """
        path = normalize_dir_path(path)
        return self._add_file_share(username, repo_id, path, 'd', password,
                                    expire_date)

    def get_dir_link_by_path(self, username, repo_id, path):
        path = normalize_dir_path(path)
        return self._get_file_share_by_path(username, repo_id, path)

    def get_valid_dir_link_by_token(self, token):
        return self._get_valid_file_share_by_token(token)

    def list_file_links(self):  # TODO: move to CE
        return super(FileShareManager, self).filter(s_type='f')


class FileShare(models.Model):
    """
    Model used for file or dir shared link.
    """
    username = LowerCaseCharField(max_length=255, db_index=True)
    repo_id = models.CharField(max_length=36, db_index=True)
    path = models.TextField()
    token = models.CharField(max_length=10, unique=True)
    ctime = models.DateTimeField(default=datetime.datetime.now)
    view_cnt = models.IntegerField(default=0)
    s_type = models.CharField(max_length=2, db_index=True, default='f') # `f` or `d`
    password = models.CharField(max_length=128, null=True)
    expire_date = models.DateTimeField(null=True)
    objects = FileShareManager()

    def is_file_share_link(self):
        return True if self.s_type == 'f' else False

    def is_dir_share_link(self):
        return False if self.is_file_share_link() else True

    def is_encrypted(self):
        return True if self.password is not None else False

    def is_expired(self):
        if self.expire_date is not None and timezone.now() > self.expire_date:
            return True
        else:
            return False

    def is_owner(self, owner):
        return owner == self.username

    def get_full_url(self):
        service_url = get_service_url().rstrip('/')
        if self.is_file_share_link():
            return '%s/f/%s/' % (service_url, self.token)
        else:
            return '%s/d/%s/' % (service_url, self.token)

    def get_name(self):         # TODO: move to CE
        return os.path.basename(self.path)

    ######################### Start PingAn Group related ##################
    def pass_verify(self):
        if not ENABLE_FILESHARE_CHECK:
            return True

        return True if self.get_status() == STATUS_PASS else False

    def is_verifing(self):
        if not ENABLE_FILESHARE_CHECK:
            return False

        return True if self.get_status() == STATUS_VERIFING else False

    def reject_verify(self):
        if not ENABLE_FILESHARE_CHECK:
            return False

        return True if self.get_status() == STATUS_VETO else False

    def get_status(self):
        if not ENABLE_FILESHARE_CHECK:
            return None

        return FileShareVerify.objects.get_status(self)

    def get_short_status_str(self):
        if not ENABLE_FILESHARE_CHECK:
            return None

        s = self.get_status()
        if s == STATUS_PASS:
            return _('Approved')
        elif s == STATUS_VERIFING:
            return _('Verifing')
        elif s == STATUS_VETO:
            return _('Rejected')

    def get_status_str(self):
        if not ENABLE_FILESHARE_CHECK:
            return None

        s = self.get_status()
        if s == STATUS_PASS:
            return _('Your share link is verified.')
        elif s == STATUS_VERIFING:
            return _('Your share link is waiting for verify.')
        elif s == STATUS_VETO:
            return _('Your share link is rejected.')

    def get_verbose_status(self):
        if not ENABLE_FILESHARE_CHECK:
            return None
        return FileShareVerify.objects.get_verbose_status(self)

    def get_verbose_status_str(self):
        rst = []
        v_stats = self.get_verbose_status()
        if v_stats is None:
            return _('No revisers found. Please contact system admin.')

        for s, v in v_stats:
            rst.append(v)

        status_str = ';'.join(rst)

        if self.pass_verify():
            status_str += '<br><br>'
            status_str += _('Link:') + ' ' + self.get_full_url()
            status_str += '<br>'
            status_str += _('Password:') + ' '
            decoded_pwd = self.get_decoded_password(self.password)
            if decoded_pwd:
                status_str += '%s' % decoded_pwd
            else:
                status_str += _('Unsupported password format, please regenerate link if you want to show password.')

        return status_str

    def get_decoded_password(self, password):
        return decode_password(password)

    def get_decoded_password_str(self):
        if not self.password:
            return None

        pwd = self.get_decoded_password(self.password)
        if pwd:
            return pwd
        else:
            return _('Unsupported password format, please regenerate link if you want to show password.')

    def need_remind(self):
        """Return `True` if department head or revisers are verifying and need
        to be remind.
        """
        fs_v = self.fileshareverify_set.all()[0]
        if fs_v.department_head_status == 0 or fs_v.reviser_status == 0:
            return True
        else:
            return False

    #################### END PingAn Group related ######################


class OrgFileShareManager(models.Manager):
    def set_org_file_share(self, org_id, file_share):
        """Set a share link as org share link.

        Arguments:
        - `org_id`:
        - `file_share`:
        """
        ofs = self.model(org_id=org_id, file_share=file_share)
        ofs.save(using=self._db)
        return ofs

class OrgFileShare(models.Model):
    """
    Model used for organization file or dir shared link.
    """
    org_id = models.IntegerField(db_index=True)
    file_share = models.OneToOneField(FileShare)
    objects = OrgFileShareManager()

    objects = OrgFileShareManager()

class UploadLinkShareManager(models.Manager):
    def _get_upload_link_by_path(self, username, repo_id, path):
        ufs = list(super(UploadLinkShareManager, self).filter(repo_id=repo_id).filter(
            username=username).filter(path=path))
        if len(ufs) > 0:
            return ufs[0]
        else:
            return None

    def get_upload_link_by_path(self, username, repo_id, path):
        path = normalize_dir_path(path)
        return self._get_upload_link_by_path(username, repo_id, path)

    def create_upload_link_share(self, username, repo_id, path,
                                 password=None, expire_date=None):
        path = normalize_dir_path(path)
        token = gen_token(max_length=10)
        if password is not None:
            password_enc = make_password(password)
        else:
            password_enc = None
        uls = super(UploadLinkShareManager, self).create(
            username=username, repo_id=repo_id, path=path, token=token,
            password=password_enc, expire_date=expire_date)
        uls.save()
        return uls

    def get_valid_upload_link_by_token(self, token):
        """Return upload link that exists and not expire, otherwise none.
        """
        try:
            fs = self.get(token=token)
        except self.model.DoesNotExist:
            return None

        if fs.expire_date is None:
            return fs
        else:
            if timezone.now() > fs.expire_date:
                return None
            else:
                return fs

class UploadLinkShare(models.Model):
    """
    Model used for shared upload link.
    """
    username = LowerCaseCharField(max_length=255, db_index=True)
    repo_id = models.CharField(max_length=36, db_index=True)
    path = models.TextField()
    token = models.CharField(max_length=10, unique=True)
    ctime = models.DateTimeField(default=datetime.datetime.now)
    view_cnt = models.IntegerField(default=0)
    password = models.CharField(max_length=128, null=True)
    expire_date = models.DateTimeField(null=True)
    objects = UploadLinkShareManager()

    def is_encrypted(self):
        return True if self.password is not None else False

    def is_owner(self, owner):
        return owner == self.username

    ######################### Start PingAn Group related ##################
    def get_decoded_password(self):
        return decode_password(self.password)

    def get_decoded_password_str(self):
        if not self.password:
            return None

        pwd = self.get_decoded_password()
        if pwd:
            return pwd
        else:
            return _('Unsupported password format, please regenerate link if you want to show password.')
    #################### END PingAn Group related ######################


class PrivateFileDirShareManager(models.Manager):
    def add_private_file_share(self, from_user, to_user, repo_id, path, perm):
        """
        """
        path = normalize_file_path(path)
        token = gen_token(max_length=10)

        pfs = self.model(from_user=from_user, to_user=to_user, repo_id=repo_id,
                         path=path, s_type='f', token=token, permission=perm)
        pfs.save(using=self._db)
        return pfs

    def add_read_only_priv_file_share(self, from_user, to_user, repo_id, path):
        """
        """
        return self.add_private_file_share(from_user, to_user, repo_id,
                                           path, 'r')

    def get_private_share_in_file(self, username, repo_id, path):
        """Get a file that private shared to ``username``.
        """
        path = normalize_file_path(path)

        ret = super(PrivateFileDirShareManager, self).filter(
            to_user=username, repo_id=repo_id, path=path, s_type='f')
        return ret[0] if len(ret) > 0 else None

    def add_private_dir_share(self, from_user, to_user, repo_id, path, perm):
        """
        """
        path = normalize_dir_path(path)
        token = gen_token(max_length=10)

        pfs = self.model(from_user=from_user, to_user=to_user, repo_id=repo_id,
                         path=path, s_type='d', token=token, permission=perm)
        pfs.save(using=self._db)
        return pfs

    def get_private_share_in_dir(self, username, repo_id, path):
        """Get a directory that private shared to ``username``.
        """
        path = normalize_dir_path(path)

        ret = super(PrivateFileDirShareManager, self).filter(
            to_user=username, repo_id=repo_id, path=path, s_type='d')
        return ret[0] if len(ret) > 0 else None

    def get_priv_file_dir_share_by_token(self, token):
        return super(PrivateFileDirShareManager, self).get(token=token)

    def delete_private_file_dir_share(self, from_user, to_user, repo_id, path):
        """
        """
        super(PrivateFileDirShareManager, self).filter(
            from_user=from_user, to_user=to_user, repo_id=repo_id,
            path=path).delete()

    def list_private_share_out_by_user(self, from_user):
        """List files/directories private shared from ``from_user``.
        """
        return super(PrivateFileDirShareManager, self).filter(
            from_user=from_user)

    def list_private_share_in_by_user(self, to_user):
        """List files/directories private shared to ``to_user``.
        """
        return super(PrivateFileDirShareManager, self).filter(
            to_user=to_user)

    def list_private_share_in_dirs_by_user_and_repo(self, to_user, repo_id):
        """List directories private shared to ``to_user`` base on ``repo_id``.
        """
        return super(PrivateFileDirShareManager, self).filter(
            to_user=to_user, repo_id=repo_id, s_type='d')

class PrivateFileDirShare(models.Model):
    from_user = LowerCaseCharField(max_length=255, db_index=True)
    to_user = LowerCaseCharField(max_length=255, db_index=True)
    repo_id = models.CharField(max_length=36, db_index=True)
    path = models.TextField()
    token = models.CharField(max_length=10, unique=True)
    permission = models.CharField(max_length=5)           # `r` or `rw`
    s_type = models.CharField(max_length=5, default='f') # `f` or `d`
    objects = PrivateFileDirShareManager()


###### signal handlers
from django.dispatch import receiver
from seahub.signals import repo_deleted

@receiver(repo_deleted)
def remove_share_links(sender, **kwargs):
    repo_id = kwargs['repo_id']

    FileShare.objects.filter(repo_id=repo_id).delete()
    UploadLinkShare.objects.filter(repo_id=repo_id).delete()


######################### Start PingAn Group related ########################
class FileShareVerifyManager(models.Manager):
    def get_status(self, share_link):
        """Return status of share link.

        0: verifing
        1: pass
        2: veto
        """
        try:
            fs_verify = self.get(share_link=share_link)
        except FileShareVerify.DoesNotExist:
            return STATUS_VERIFING

        if fs_verify.DLP_status == STATUS_PASS and \
           fs_verify.department_head_status == STATUS_PASS and \
           fs_verify.reviser_status == STATUS_PASS:
            return STATUS_PASS

        if fs_verify.DLP_status == STATUS_VETO or \
           fs_verify.department_head_status == STATUS_VETO or \
           fs_verify.reviser_status == STATUS_VETO:
            return STATUS_VETO

        return STATUS_VERIFING

    def get_verbose_status(self, share_link):
        """Return verbose status of share link.

        e.g.
        [(0, 'Awating DLP verifing'), (0, 'Awaiting department head verifing'),
        [0, 'Awaiting reviser verifing]]
        """

        try:
            fs_verify = self.get(share_link=share_link)
        except FileShareVerify.DoesNotExist:
            return None

        from seahub.share.share_link_checking import get_reviser_info_by_user
        reviser_info = get_reviser_info_by_user(share_link.username)
        if reviser_info is None:
            return None

        # genetate DLP status
        if fs_verify.DLP_status == STATUS_VERIFING:
            dlp_msg = _('Awaiting DLP verifing')

        elif fs_verify.DLP_status == STATUS_PASS:

            if fs_verify.DLP_vtime:
                dlp_msg = _('DLP passed at %s') % fs_verify.DLP_vtime.strftime('%Y-%m-%d')
            else:
                dlp_msg = _('DLP passed')

        elif fs_verify.DLP_status == STATUS_VETO:

            if fs_verify.DLP_vtime:
                dlp_msg = _('DLP veto at %s') % fs_verify.DLP_vtime.strftime('%Y-%m-%d')
            else:
                dlp_msg = _('DLP veto')

        # genetate department head status
        department_head_info = _('department head (%(name)s %(email)s)') % {
            'name': reviser_info.department_head_name,
            'email': reviser_info.department_head_email
        }

        if fs_verify.department_head_status == STATUS_VERIFING:
            dept_head_msg = _('Awaiting %s verifing') % department_head_info

        elif fs_verify.department_head_status == STATUS_PASS:

            if fs_verify.department_head_vtime:
                dept_head_msg = _('%(info)s passed at %(date)s') % {
                    'info': department_head_info,
                    'date': fs_verify.department_head_vtime.strftime('%Y-%m-%d')
                }
            else:
                dept_head_msg = _('%s passed') % department_head_info

        elif fs_verify.department_head_status == STATUS_VETO:

            if fs_verify.department_head_vtime:
                dept_head_msg = _('%(info)s veto at %(date)s') % {
                    'info': department_head_info,
                    'date': fs_verify.department_head_vtime.strftime('%Y-%m-%d')
                }
            else:
                dept_head_msg = _('%s veto') % department_head_info

        # genetate reviser status
        revisers_info = _('revisers (%(name1)s %(email1)s, %(name2)s %(email2)s)') % {
            'name1': reviser_info.reviser1_name,
            'email1': reviser_info.reviser1_email,
            'name2': reviser_info.reviser2_name,
            'email2': reviser_info.reviser2_email
        }
        if fs_verify.reviser_status == STATUS_VERIFING:
            reviser_msg = _('Awaiting %s verifing') % revisers_info

        elif fs_verify.reviser_status == STATUS_PASS:

            if fs_verify.reviser_vtime:
                reviser_msg = _('%(info)s passed at %(date)s') % {
                    'info': revisers_info,
                    'date': fs_verify.reviser_vtime.strftime('%Y-%m-%d'),
                }
            else:
                reviser_msg = _('%s passed') % revisers_info

        elif fs_verify.reviser_status == STATUS_VETO:

            if fs_verify.reviser_vtime:
                reviser_msg = _('%(info)s veto at %(date)s') % {
                    'info': revisers_info,
                    'date': fs_verify.reviser_vtime.strftime('%Y-%m-%d'),
                }
            else:
                reviser_msg = _('%s veto') % revisers_info

        return [(fs_verify.DLP_status, dlp_msg),
                (fs_verify.department_head_status, dept_head_msg),
                (fs_verify.reviser_status, reviser_msg)]

    def set_status(self, share_link, status, username):
        """Set status depending the type of user.
        """
        m = self.get(share_link=share_link)

        from seahub.share.share_link_checking import get_reviser_emails_by_user
        revisers = get_reviser_emails_by_user(share_link.username)
        if not revisers:
            return m

        if username == revisers[0]:
            m.department_head_status = status
            m.department_head_vtime = datetime.datetime.now()

        if username == revisers[1]:
            m.comanager_head_status = status
            m.comanager_head_vtime = datetime.datetime.now()

        if username == revisers[2] or username == revisers[3]:
            if m.reviser_status == STATUS_VERIFING:
                # Only set reviser status when it's not reviewed
                m.reviser_status = status
                m.reviser_vtime = datetime.datetime.now()

        m.save()
        return m

class FileShareVerify(models.Model):
    STATUS_CHOICES = (
        (STATUS_VERIFING, 'Verifing'),
        (STATUS_PASS, 'Pass'),
        (STATUS_VETO, 'Veto')
    )

    share_link = models.ForeignKey(FileShare)
    DLP_status = models.IntegerField(choices=STATUS_CHOICES,
                                     default=STATUS_VERIFING)
    DLP_vtime = models.DateTimeField(blank=True, null=True)
    department_head_status = models.IntegerField(choices=STATUS_CHOICES,
                                                 default=STATUS_VERIFING)
    department_head_vtime = models.DateTimeField(blank=True, null=True)
    comanager_head_status = models.IntegerField(choices=STATUS_CHOICES,
                                                default=STATUS_VERIFING) # not used yet
    comanager_head_vtime = models.DateTimeField(blank=True, null=True)
    reviser_status = models.IntegerField(choices=STATUS_CHOICES,
                                         default=STATUS_VERIFING)
    reviser_vtime = models.DateTimeField(blank=True, null=True)

    objects = FileShareVerifyManager()

    def department_head_pass(self):
        return True if self.department_head_status == STATUS_PASS else False

    def department_head_veto(self):
        return True if self.department_head_status == STATUS_VETO else False

    def comanager_head_pass(self):
        return True if self.comanager_head_status == STATUS_PASS else False

    def comanager_head_veto(self):
        return True if self.comanager_head_status == STATUS_VETO else False

    def revisers_pass(self):
        return True if self.reviser_status == STATUS_PASS else False

    def revisers_veto(self):
        return True if self.reviser_status == STATUS_VETO else False


class FileShareReviserInfoManager(models.Manager):
    def add_file_share_reviser(
            self, department_name, department_head_name,
            department_head_account, department_head_email, comanager_head_name,
            comanager_head_account, comanager_head_email, reviser1_name,
            reviser1_account, reviser1_email, reviser2_name, reviser2_account,
            reviser2_email):

        reviser = self.model(department_name=department_name,
                             department_head_name=department_head_name,
                             department_head_account=department_head_account,
                             department_head_email=department_head_email,
                             comanager_head_name=comanager_head_name,
                             comanager_head_account=comanager_head_account,
                             comanager_head_email=comanager_head_email,
                             reviser1_name=reviser1_name,
                             reviser1_account=reviser1_account,
                             reviser1_email=reviser1_email,
                             reviser2_name=reviser2_name,
                             reviser2_account=reviser2_account,
                             reviser2_email=reviser2_email)

        reviser.save(using=self._db)

        return reviser


class FileShareReviserInfo(models.Model):
    department_name = models.CharField(max_length=200, db_index=True)
    department_head_name = models.CharField(max_length=1024)
    department_head_account = models.CharField(max_length=1024)
    department_head_email = models.EmailField()
    comanager_head_name = models.CharField(max_length=1024)
    comanager_head_account = models.CharField(max_length=1024)
    comanager_head_email = models.EmailField()
    reviser1_name = models.CharField(max_length=1024)
    reviser1_account = models.CharField(max_length=1024)
    reviser1_email = models.EmailField()
    reviser2_name = models.CharField(max_length=1024)
    reviser2_account = models.CharField(max_length=1024)
    reviser2_email = models.EmailField()

    objects = FileShareReviserInfoManager()

    def __unicode__(self):
        return '%s <--> %s %s %s' % (self.department_name, self.department_head_email, self.reviser1_email, self.reviser2_email)


class FileShareReviserMap(models.Model):
    """Direct map for user and revisor, if there is a record in this table,
    we will not use department relation for revisors anymore.
    """
    username = LowerCaseCharField(max_length=255, db_index=True)
    reviser_name = models.CharField(max_length=1024)
    reviser_account = models.CharField(max_length=1024)
    reviser_email = models.EmailField()

    def __unicode__(self):
        return '%s <--> %s (%s)' % (self.username, self.reviser_name, self.reviser_email)

class FileShareVerifyIgnore(models.Model):
    """Ignore user from share link verification. In some usercases, boss does
    not want to be verified when generate shared link.
    """
    username = LowerCaseCharField(max_length=255)


class FileShareReceiverManager(models.Manager):
    def batch_add_emails(self, share_link, emails):
        """Batch add receiver emails.
        """
        if not emails:
            return

        added = list(self.filter(share_link=share_link))
        for email in set(emails):
            if email in added:
                continue

            self.model(share_link=share_link, email=email).save()


class FileShareReceiver(models.Model):
    share_link = models.ForeignKey(FileShare)
    email = models.CharField(max_length=255)
    phone = models.CharField(max_length=50, blank=True, null=True)
    objects = FileShareReceiverManager()


class FileShareDownloadsManager(models.Manager):
    def add(self, share_link, username):
        """Record download info.

        Arguments:
        - `self`:
        - `share_link`:
        - `username`:
        """
        if len(self.filter(share_link=share_link, is_first_download=True)) > 0:
            is_first_download = False
        else:
            if share_link.pass_verify() and username != share_link.username:
                is_first_download = True
            else:
                is_first_download = False

        o = self.model(share_link=share_link, download_time=timezone.now(),
                       is_first_download=is_first_download)
        o.save(using=self._db)
        return o

    def get_first_download_time(self, share_link):
        r = self.filter(share_link=share_link, is_first_download=True)
        return r[0].download_time if r else None


class FileShareDownloads(models.Model):
    """
    Model used to record download info(download time, etc..)
    """
    share_link = models.ForeignKey(FileShare)
    download_time = models.DateTimeField()
    is_first_download = models.BooleanField()
    objects = FileShareDownloadsManager()


class UploadLinkShareUploads(models.Model):
    """
    Model used to record upload info(file name, upload time, IP, etc..).
    """
    upload_link = models.ForeignKey(UploadLinkShare)
    file_name = models.CharField(max_length=2048)
    file_size = models.BigIntegerField()
    upload_time = models.DateTimeField(db_index=True)
    upload_ip = models.CharField(max_length=20, db_index=True)


########## Handle signals to remove file share
from django.dispatch import receiver
from seahub.signals import file_deleted, file_edited

@receiver([file_deleted, file_edited])
def file_updated_cb(sender, **kwargs):
    """Remove file share when file is deleted/edited/replaced.

    Arguments:
    - `sender`:
    - `**kwargs`:
    """
    repo_id = kwargs['repo_id']
    parent_dir = kwargs['parent_dir']
    file_name = kwargs['file_name']
    username = kwargs['username']
    path = posixpath.join(parent_dir, file_name)

    FileShare.objects.filter(username=username).filter(
        repo_id=repo_id).filter(path=path).delete()

######################## End PingAn Group related ##########################
