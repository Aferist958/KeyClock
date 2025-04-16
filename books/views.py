from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from keycloak import KeycloakOpenID
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from config.settings import KEYCLOAK_CONFIG
from .models import Book
from .serializers import BookSerializer
from rest_framework.permissions import IsAuthenticated


class KeycloakLoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        
        keycloak_openid = KeycloakOpenID(
            server_url=KEYCLOAK_CONFIG['SERVER_URL'],
            client_id=KEYCLOAK_CONFIG['CLIENT_ID'],
            realm_name=KEYCLOAK_CONFIG['REALM_NAME'],
            client_secret_key=KEYCLOAK_CONFIG['CLIENT_SECRET_KEY'],
        )
        
        try:
            token = keycloak_openid.token(username, password)
            return Response(token)
        except Exception as e:
            return Response(
                {'error': str(e)}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        

class BookListCreate(ListCreateAPIView):
    queryset = Book.objects.all()
    serializer_class = BookSerializer
    permission_classes = [IsAuthenticated]


class BookRetrieveUpdateDestroy(RetrieveUpdateDestroyAPIView):
    queryset = Book.objects.all()
    serializer_class = BookSerializer
    permission_classes = [IsAuthenticated]
