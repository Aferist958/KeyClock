from rest_framework import authentication, exceptions
from keycloak import KeycloakOpenID
from django.conf import settings

class KeycloakAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        
        if not auth_header:
            return None
            
        try:
            keycloak_openid = KeycloakOpenID(
                server_url=settings.KEYCLOAK_CONFIG['SERVER_URL'],
                client_id=settings.KEYCLOAK_CONFIG['CLIENT_ID'],
                realm_name=settings.KEYCLOAK_CONFIG['REALM_NAME'],
                client_secret_key=settings.KEYCLOAK_CONFIG['CLIENT_SECRET_KEY'],
            )
            
            token = auth_header.split(' ')[1]
            
            userinfo = keycloak_openid.userinfo(token)
            introspect = keycloak_openid.introspect(token)
            
            if not introspect['active']:
                raise exceptions.AuthenticationFailed('Invalid token')
                
            user = self.get_or_create_user(userinfo)
            
            return (user, None)
            
        except Exception as e:
            raise exceptions.AuthenticationFailed(str(e))
    
    def get_or_create_user(self, userinfo):
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        try:
            user = User.objects.get(username=userinfo['preferred_username'])
        except User.DoesNotExist:
            user = User.objects.create_user(
                username=userinfo['preferred_username'],
                email=userinfo.get('email', ''),
            )
        
        return user