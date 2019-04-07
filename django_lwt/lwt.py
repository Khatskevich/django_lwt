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

SETTINGS = {
        'APP_VERSION': 0,
        'EXPIRATION': 60 * 60 * 24 * 365,
        'SAVE_USER_FIELDS': []
        }

if hasattr(settings, 'LWT_AUTHENTICATION'):
    explicit_settings = settings.LWT_AUTHENTICATION
    for key in SETTINGS.keys():
        if key in explicit_settings:
            SETTINGS[key] = explicit_settings[key]
    uf = SETTINGS['SAVE_USER_FIELDS']
    uf = set(uf) - {'id', 'pk'}
    SETTINGS['SAVE_USER_FIELDS'] = list(uf)


class BaseLWTAuthentication(BaseAuthentication):
    """
    Base auth class based on Byte Web Token standard.
    """
    LWT_AUTH_COOKIE = 'lwt'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.bwt = BWT(settings.SECRET_KEY)

    def get_lwt_value(self, request):
        auth = get_authorization_header(request).split()

        if not auth:
            return request.COOKIES.get(self.LWT_AUTH_COOKIE)
        auth_header_prefix = 'lwt'
        if auth[0].decode('utf-8').lower() != auth_header_prefix:
            return None
        return auth[1]

    def authenticate(self, request):
        lwt_value = self.get_lwt_value(request)
        if lwt_value is None:
            return None
        try:
            data = self.bwt.decode(lwt_value)
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
        return None

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
    def login(self, user, request, set_cookie=None, **kwargs):
        pk = user.pk
        if isinstance(pk, uuid.UUID):
            pk = str(pk)
        msg = {
                # Explicitly convert to string, for tupes
                'pk': str(user.id)
                }
        for field in SETTINGS['SAVE_USER_FIELDS']:
            msg[field] = getattr(user, field)
        msg = json.dumps(
                msg, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        exp_time = int(time.time()) + SETTINGS['EXPIRATION']
        token = self.bwt.encode(
                msg, app_version=SETTINGS['APP_VERSION'], exp=exp_time)
        return token

    def get_user(self, data):
        user = self.get_blank_user(data['msg']['pk'])
        for field in SETTINGS['SAVE_USER_FIELDS']:
            setattr(user, field, data['msg'][field])
        return user

    def validate_msg(self, msg):
        return json.loads(msg)
