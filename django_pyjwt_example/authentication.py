from django.conf import settings
import jwt
from django.contrib.auth import get_user_model, user_logged_in
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed
import jsonschema


class JWTAuthentication(BaseAuthentication):
    token_schema = {
        'type': 'object',
        'properties': {
            'username': {'type': 'string'},
            'exp': {'type': 'integer'}
        },
        'required': ['username', 'exp']
    }

    def authenticate(self, request):
        auth = get_authorization_header(request).split()
        # An authorization with a JWT token typically starts with `Bearer`
        # https://jwt.io/introduction/
        # Only continue this authentication method if the header consists of
        # the word 'Bearer' and a token
        if len(auth) != 2 or auth[0].decode() != 'Bearer':
            return None
        _, encoded_token = auth
        try:
            token = jwt.decode(encoded_token, settings.JWT_PUBLIC_KEY, algorithms=['RS512'])
        except jwt.exceptions.DecodeError:
            raise AuthenticationFailed('Malformed token')

        try:
            jsonschema.validate(token, JWTAuthentication.token_schema)
        except jsonschema.ValidationError as e:
            raise AuthenticationFailed({
                'detail': f'Invalid JWT schema: {e.message}',
                'schema': e.schema
            }, 400)

        user, created = get_user_model().objects.get_or_create(username=token['username'])
        # Sending a signal allows Django proper population of fields like last_login
        user_logged_in.send(sender=JWTAuthentication, request=request, user=user)
        return user, None
