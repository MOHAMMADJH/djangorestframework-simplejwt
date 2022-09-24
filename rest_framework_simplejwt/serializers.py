from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import update_last_login
from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions, serializers
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt import exceptions as _exp
from collections import OrderedDict

from .settings import api_settings
from .tokens import RefreshToken, SlidingToken, UntypedToken
from django.db.models import Q # new lib

if api_settings.BLACKLIST_AFTER_ROTATION:
    from .token_blacklist.models import BlacklistedToken


class PasswordField(serializers.CharField):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('style', {})

        kwargs['style']['input_type'] = 'password'
        kwargs['write_only'] = True

        super().__init__(*args, **kwargs)


class TokenObtainSerializer(serializers.Serializer):
    username_field = get_user_model().USERNAME_FIELD
    default_error_messages = {
        'no_active_account': _('No active account found with the given credentials'),
        'account_Not_found':_('account_Not_found')
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields[self.username_field] = serializers.CharField()
        self.fields['password'] = PasswordField()
    def validate(self, attrs):
        user_filled =  str(attrs[self.username_field])
        # ############################################# #
        print(user_filled)
        user = get_user_model() # git user Class
        # filter data come from get User TOKEN Endpoint and Chick the user it is in the system
        c_user = user.objects.filter(Q(phone_number = user_filled) | Q(email = user_filled) |  Q(username = user_filled))
        print('## C_USER')
        print(c_user)
        attrs_dict = dict(attrs)
        print(attrs_dict)
        try:

            attrs_dict['email'] = c_user.first().email
        except:
            raise _exp.AuthenticationFailed(
                self.error_messages['account_Not_found'],
                'account_Not_found',)
        attrs_ordar = OrderedDict()
        attrs_ordar['email'] = attrs_dict['email']
        attrs_ordar['password'] = attrs_dict['password']

        # ############################################ #
        authenticate_kwargs = {
            self.username_field: attrs_ordar[self.username_field],
            'password': attrs_ordar['password'],
        }
        try:
            authenticate_kwargs['request'] = self.context['request']
            print(self.context['request'])
        except KeyError:
            pass

        self.user = authenticate(**authenticate_kwargs)

        if not api_settings.USER_AUTHENTICATION_RULE(self.user):
            raise _exp.ActivationFailed(
                self.error_messages['no_active_account'],
                'no_active_account',
            )

        return {}

    @classmethod
    def get_token(cls, user):
        raise NotImplementedError('Must implement `get_token` method for `TokenObtainSerializer` subclasses')


class TokenObtainPairSerializer(TokenObtainSerializer):
    @classmethod
    def get_token(cls, user):
        return RefreshToken.for_user(user)

    def validate(self, attrs):
        data = super().validate(attrs)

        refresh = self.get_token(self.user)

        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)

        if api_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, self.user)

        return data


class TokenObtainSlidingSerializer(TokenObtainSerializer):
    @classmethod
    def get_token(cls, user):
        return SlidingToken.for_user(user)

    def validate(self, attrs):
        data = super().validate(attrs)

        token = self.get_token(self.user)

        data['token'] = str(token)

        if api_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, self.user)

        return data


class TokenRefreshSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    access = serializers.ReadOnlyField()

    def validate(self, attrs):
        refresh = RefreshToken(attrs['refresh'])

        data = {'access': str(refresh.access_token)}

        if api_settings.ROTATE_REFRESH_TOKENS:
            if api_settings.BLACKLIST_AFTER_ROTATION:
                try:
                    # Attempt to blacklist the given refresh token
                    refresh.blacklist()
                except AttributeError:
                    # If blacklist app not installed, `blacklist` method will
                    # not be present
                    pass

            refresh.set_jti()
            refresh.set_exp()

            data['refresh'] = str(refresh)

        return data


class TokenRefreshSlidingSerializer(serializers.Serializer):
    token = serializers.CharField()

    def validate(self, attrs):
        token = SlidingToken(attrs['token'])

        # Check that the timestamp in the "refresh_exp" claim has not
        # passed
        token.check_exp(api_settings.SLIDING_TOKEN_REFRESH_EXP_CLAIM)

        # Update the "exp" claim
        token.set_exp()

        return {'token': str(token)}


class TokenVerifySerializer(serializers.Serializer):
    token = serializers.CharField()

    def validate(self, attrs):
        token = UntypedToken(attrs['token'])

        if api_settings.BLACKLIST_AFTER_ROTATION:
            jti = token.get(api_settings.JTI_CLAIM)
            if BlacklistedToken.objects.filter(token__jti=jti).exists():
                raise ValidationError("Token is blacklisted")

        return {}
