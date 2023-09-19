from django.urls import path
from api import views

urlpatterns = [
    path('schoolclass/<int:id>', views.get_class_data),
    path('login/<str:username>/<str:password>', views.login),
    path('get_csrf_token/', views.get_csrf_token_view)
]