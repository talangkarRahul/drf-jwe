import jwt
import datetime
import logging

from jwcrypto import jwe, jwk
from jwcrypto.common import json_encode


from django.utils import timezone
from django.conf import settings


logger = logging.getLogger(__name__)


def jwt_encode_handler(payload):
    key = settings.jwt_secret
    return jwt.encode(
        payload,
        key,
        settings.JWT_DEFAULTS['JWT_ALGORITHM']
    ).decode('utf-8')


def jwt_decode_handler(token, options=None):
    if options is None:
        options = {
         'verify_exp': settings.JWT_DEFAULTS['JWT_VERIFY_EXPIRATION'],
        }
    secret_key = settings.jwt_secret
    return jwt.decode(
        token,
        secret_key,
        options=options,
        leeway=settings.JWT_DEFAULTS['JWT_LEEWAY'],
        audience=settings.JWT_DEFAULTS['JWT_AUDIENCE'],
        issuer=settings.JWT_DEFAULTS['JWT_ISSUER'],
        algorithms=[settings.JWT_DEFAULTS['JWT_ALGORITHM']]
    )


def generate_jwt_payload(user):
    payload = {
        'user_id': user.id,
        'iss': settings.JWT_DEFAULTS['JWT_ISSUER'],
        'iat': timezone.localtime(),
        'exp': timezone.localtime() + datetime.timedelta(days=14)
    }
    return payload


def jwe_encode_handler(payload):
    key = jwk.JWK(**{
        'k': settings.jwe_secret,
        'kty': settings.JWE_DEFAULTS['JWE_KEY_TYPE'],
    })
    jwe_token = jwe.JWE(payload.encode('utf-8'), json_encode({
        "alg": settings.JWE_DEFAULTS['JWE_ALGORITHM'],
        "enc": settings.JWE_DEFAULTS['JWE_ENCODER']
    }))
    jwe_token.add_recipient(key)
    token = jwe_token.serialize('json')
    return token


def jwe_decode_handler(token):

    key = jwk.JWK(**{
        'k': settings.jwe_secret,
        'kty': settings.JWE_DEFAULTS['JWE_KEY_TYPE'],
    })
    jwe_token = jwe.JWE()
    jwe_token.deserialize(token)
    jwe_token.decrypt(key)
    return jwe_token.payload


def token_encode(user):
    payload = generate_jwt_payload(user)
    jwt_token = jwt_encode_handler(payload)
    jwe_token = jwe_encode_handler(jwt_token)
    return jwe_token


def token_decode(token):
    jwt_token = jwe_decode_handler(token)
    payload = jwt_decode_handler(jwt_token)
    return payload
