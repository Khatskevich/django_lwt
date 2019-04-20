from django.conf import settings
import uuid
import time
from .bwt import BWT
from rest_framework.authentication import (
    BaseAuthentication, get_authorization_header
)
from rest_framework import exceptions as REx
from . import exceptions as BEx
import json
from django.contrib.auth import get_user_model

__SETTINGS = {
        'APP_VERSION': 0,
        # When the token cannot be trusted.
        'SIGNATURE_EXPIRATION': 60 * 60 * 24 * 365,
        # When data should be updated from db.
        'DATA_EXPIRATION': 60 * 60 * 24 * 14,
        # User fields to be stored in token. Can be accessed without
        # querying db.
        'SAVE_USER_FIELDS': [],
        'COOKIE_NAME': 'lwt',
        'AUTH_HEADER_PREFIX': 'lwt',
        }

__INITIALIZED = False


def __init_settings():
    global __INITIALIZED
    if __INITIALIZED:
        return
    if not hasattr(settings, 'LWT_AUTHENTICATION'):
        return
    explicit_settings = settings.LWT_AUTHENTICATION
    for key in __SETTINGS.keys():
        if key in explicit_settings:
            __SETTINGS[key] = explicit_settings[key]
    uf = __SETTINGS['SAVE_USER_FIELDS']
    uf = set(uf) - {'id', 'pk'}
    __SETTINGS['SAVE_USER_FIELDS'] = list(uf)
    __INITIALIZED = True


class BaseLWTAuthentication(BaseAuthentication):
    """
    Base auth class based on Byte Web Token standard.
    """

    def __init__(self, *args, **kwargs):
        __init_settings()
        super().__init__(*args, **kwargs)
        self.bwt = BWT(settings.SECRET_KEY)

    def get_lwt_value(self, request):
        auth = get_authorization_header(request).split()

        if not auth:
            return request.COOKIES.get(__SETTINGS['COOKIE_NAME'])
        if auth[0].decode('utf-8').lower() != __SETTINGS['AUTH_HEADER_PREFIX']:
            return None
        return auth[1]

    def authenticate(self, request):
        lwt_value = self.get_lwt_value(request)
        if lwt_value is None:
            return None
        try:
            issue_max_time = int(time.time()) - __SETTINGS['SIGNATURE_EXPIRATION']
            data = self.bwt.decode(lwt_value, issue_max_time)
        except BEx.BWTExpired:
            raise REx.AuthenticationFailed("Signature expired")
        except BEx.BWTException:
            raise REx.AuthenticationFailed()

        data['msg'] = self.validate_msg(data['msg'])
        user = self.authenticate_credentials(data)
        return (user, data)

    def authenticate_credentials(self, data):
        user = self.get_user(data)
        return user

    def get_user(self, data):
        raise NotImplementedError()

    def get_blank_user(self, pk):
        User = get_user_model()
        user = User.from_db(None, ['id'], [pk])

        def rfdb(*args, **kwargs):
            # In case non-saved field is accessed for the first
            # time, refresh all fields.
            self = user
            deferred_fields = self.get_deferred_fields()
            self.lwt_refresh_from_db(fields=deferred_fields)
            # TODO: check that existing fields did not change
            self.refresh_from_db = self.lwt_refresh_from_db
        user.lwt_refresh_from_db = user.refresh_from_db
        user.refresh_from_db = rfdb
        return user

    def validate_msg(self, msg):
        return msg


class LWTAuthentication(BaseLWTAuthentication):
    def login(self, user, request, **kwargs):
        pk = user.pk
        if isinstance(pk, uuid.UUID):
            pk = str(pk)
        msg = {
                # Explicitly convert to string (for uuid)
                'pk': str(user.id)
                }
        for field in __SETTINGS['SAVE_USER_FIELDS']:
            msg[field] = getattr(user, field)
        msg = json.dumps(
                msg, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        token = self.bwt.encode(
                msg, app_version=__SETTINGS['APP_VERSION'])
        return token

    def set_cookie(self, response, token):
        response.set_cookie(__SETTINGS['COOKIE_NAME'], token,
                            max_age=__SETTINGS['SIGNATURE_EXPIRATION'])

    def get_user(self, data):
        user = self.get_blank_user(data['msg']['pk'])
        # Data is expired
        if data['issue_time'] + __SETTINGS['DATA_EXPIRATION'] < time.time():
            data['data_expired'] == True
            return user
        for field in __SETTINGS['SAVE_USER_FIELDS']:
            setattr(user, field, data['msg'][field])
        return user

    def validate_msg(self, msg):
        return json.loads(msg)
