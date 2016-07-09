from django import forms
from django.utils.translation import ugettext_lazy as _

class RepoShareForm(forms.Form):
    """
    Form for sharing repo to user or group.
    """

    email_or_group = forms.CharField(max_length=512)
    repo_id = forms.CharField(max_length=36)
    permission = forms.ChoiceField(choices=(('rw', 'read-write'), ('r', 'read-only')))

class FileLinkShareForm(forms.Form):
    """
    Form for sharing file shared link to emails.
    """

    email = forms.CharField(max_length=512, error_messages={
            'required': _("Email is required"),
            'max_length': _("Email is not longer than 512 characters"),
            })
    file_shared_link = forms.CharField()
    extra_msg = forms.CharField(required=False)
    file_shared_name = forms.CharField()
    file_shared_type = forms.CharField()
    
class UploadLinkShareForm(forms.Form):
    """
    Form for sharing upload link to emails.
    """
    email = forms.CharField(max_length=512, error_messages={
            'required': _("Email is required"),
            'max_length': _("Email is not longer than 512 characters"),
            })
    shared_upload_link = forms.CharField()
    extra_msg = forms.CharField(required=False)

######################### Start PingAn Group related ########################
from django.core.cache import cache
from captcha.fields import CaptchaField
from .hashers import check_password
from .utils import get_unusable_verify_code

class SharedLinkPasswordForm(forms.Form):
    """
    Form for user to access encrypted shared files/directory.
    """
    token = forms.CharField()
    password = forms.CharField(error_messages={'required': _('Password can\'t be empty')})
    enc_password = forms.CharField()
    verify_code = forms.CharField(error_messages={'required': _('Verify code can not be empty')})

    def clean_verify_code(self):
        if self.cleaned_data['verify_code'] == get_unusable_verify_code():
            return

        token = self.cleaned_data['token']
        cache_key = 'share_link_verify_code_%s' % token
        code = cache.get(cache_key)
        if code != self.cleaned_data['verify_code']:
            raise forms.ValidationError(_("Invalid verify code"))

    def clean(self):
        password = self.cleaned_data['password']
        enc_password = self.cleaned_data['enc_password']
        if not check_password(password, enc_password):
            raise forms.ValidationError(_("Please enter a correct password."))

        return self.cleaned_data

class CaptchaSharedLinkPasswordForm(SharedLinkPasswordForm):
    captcha = CaptchaField()
######################### End PingAn Group related ##########################
