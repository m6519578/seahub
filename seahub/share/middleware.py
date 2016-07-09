from seahub.share.share_link_checking import is_file_link_reviser

class FileLinkVerifyMiddleware(object):
    """Check if current user is file link reviser.
    """
    def process_request(self, request):
        if is_file_link_reviser(request.user.username):
            request.user.is_file_link_reviser = True
        else:
            request.user.is_file_link_reviser = False

        return None
