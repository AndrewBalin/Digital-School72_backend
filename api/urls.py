from django.urls import path
from api import views

urlpatterns = [
    path('schoolclass/<int:id>', views.get_class_data),
    path('login', views.login),
    path('get_csrf_token', views.get_csrf_token_view),
    path('get_user_name/<int:id>', views.get_user_name),
    path('get_user_email/<int:id>', views.get_user_email),
    path('get_user/<int:id>', views.get_user_profile)
]