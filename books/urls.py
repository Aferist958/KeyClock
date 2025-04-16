from django.urls import path
from .views import BookListCreate, BookRetrieveUpdateDestroy, KeycloakLoginView

urlpatterns = [
    path('login/', KeycloakLoginView.as_view(), name="login"),
    path('books/', BookListCreate.as_view(), name="books_create_list"),
    path('books/<int:pk>/', BookRetrieveUpdateDestroy.as_view(), name="books_retrieve_update_delete"),
]
