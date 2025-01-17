from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions, status
from rest_framework.exceptions import _get_error_details, APIException

class TokenError(Exception):
    pass


class TokenBackendError(Exception):
    pass


class DetailDictMixin:
    def __init__(self, detail=None, code=None):
        """
        Builds a detail dictionary for the error to give more information to API
        users.
        """
        detail_dict = {'detail': self.default_detail, 'code': self.default_code}

        if isinstance(detail, dict):
            detail_dict.update(detail)
        elif detail is not None:
            detail_dict['detail'] = detail

        if code is not None:
            detail_dict['code'] = code

        super().__init__(detail_dict)


class AuthenticationFailed(DetailDictMixin, exceptions.AuthenticationFailed):
    pass


class InvalidToken(AuthenticationFailed):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = _('Token is invalid or expired')
    default_code = 'token_not_valid'



class AuthenticationFailed(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = _('Incorrect authentication credentials.')
    default_code = 'authentication_failed'

class ActivationFailed(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = _('Incorrect authentication credentials.')
    default_code = 'authentication_failed'

