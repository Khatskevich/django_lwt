# Lightweight Web Token
LWT is yet another approach to authenticate your user.
LWT is based on Byte Web Token, implemented in the same package.

LWT is similar to JWT and has two main goals:
1. Introduce smaller size amplification.
2. (Django specific) Avoid calls to database when accessing limited set
of user fields.

## Usage

In your `settings.py`:
```
LWT_AUTHENTICATION = {
        'APP_VERSION': 0,
        'EXPIRATION': 60 * 60 * 24 * 365,
        'SAVE_USER_FIELDS': ['type', 'email']
        }

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'django_lwt.LWTAuthentication',
    )
```

Login view:
```
lwt = LWTAuthentication()
token = lwt.login(user, request)
```

HTTP request header:
```
'Authorization: LWT {token}'
```

## BWT Message format
header.data.signature

### Header
Header consists of:
1. 1 byte BWT version
2. 1 byte user app version (in case data format changes)
3. 4 byte issue time

### Data
Data can be any byte array, which allows more space efficient custom
encodings.
Data is not encrypted in current LWT version.

### Signature
Signature works the same as in JWT. In future format version, there is
an idea to get rid of the signature and use symmetric data encryption only (to
save space).
