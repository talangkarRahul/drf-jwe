# drf-jwe

### Add in settings
``` python 
  JWT_DEFAULTS = {
    'JWT_VERIFY_EXPIRATION': True,
    'JWT_LEEWAY': 0,
    'JWT_VERIFY': True,
    'JWT_AUDIENCE': None,
    'JWT_ISSUER': 'indiaaclick',
    'JWT_ALGORITHM': 'HS256',
}

JWE_DEFAULTS = {
    'JWE_KEY_TYPE': 'oct',
    "JWE_ALGORITHM": "A256KW",
    "JWE_ENCODER": "A256CBC-HS512"
}

REST_FRAMEWORK = {
  # other settings
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'drf_jwe.authentication.JSONWebTokenAuthentication',
    ),
}


AUTH_USER_MODEL = 'user_mgmt.UserMaster' # your user model
```

### Dependency packages:

* pyjwt
* djangorestframework==3.11.0
* jwcrypto==0.7
