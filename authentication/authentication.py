# authentication/authentication.py

from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.utils import timezone
from .models import CustomAuthToken


class CustomTokenAuthentication(BaseAuthentication):
    """
    Custom token authentication class that handles both staff and user tokens
    with different expiry rules
    """
    keyword = 'Token'
    model = CustomAuthToken

    def authenticate(self, request):
        """
        Authenticate the request and return a two-tuple of (user, token)
        """
        auth = self.get_authorization_header(request).split()

        if not auth or auth[0].lower() != self.keyword.lower().encode():
            return None

        if len(auth) == 1:
            msg = 'Invalid token header. No credentials provided.'
            raise AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = 'Invalid token header. Token string should not contain spaces.'
            raise AuthenticationFailed(msg)

        try:
            token = auth[1].decode()
        except UnicodeError:
            msg = 'Invalid token header. Token string should not contain invalid characters.'
            raise AuthenticationFailed(msg)

        return self.authenticate_credentials(token)

    def authenticate_credentials(self, key):
        """
        Authenticate the token key and return the user and token
        """
        try:
            token = self.model.objects.select_related('user').get(token=key)
        except self.model.DoesNotExist:
            raise AuthenticationFailed('Invalid token.')

        if not token.is_active:
            raise AuthenticationFailed('Token has been revoked.')

        if not token.user.is_active:
            raise AuthenticationFailed('User account is disabled.')

        # Check token expiry
        if token.expires_at and timezone.now() > token.expires_at:
            # Mark token as inactive
            token.is_active = False
            token.save(update_fields=['is_active'])
            raise AuthenticationFailed('Token has expired.')

        # Update last used timestamp
        token.update_last_used()

        return (token.user, token)

    def get_authorization_header(self, request):
        """
        Return request's 'Authorization:' header, as a bytestring.
        """
        auth = request.META.get('HTTP_AUTHORIZATION', b'')
        if isinstance(auth, str):
            auth = auth.encode('iso-8859-1')
        return auth

    def authenticate_header(self, request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response, or `None` if the
        authentication scheme should return `403 Permission Denied` responses.
        """
        return self.keyword