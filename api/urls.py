from django.urls import path
from api import views

urlpatterns = [
    path('get_schoolclass/<int:id>', views.get_class_data),
    path('login', views.login),
    path('get_csrf_token', views.get_csrf_token_view),
    path('get_user_name/<int:id>', views.get_user_name),
    path('get_user_email/<int:id>', views.get_user_email),
    path('get_user/<int:id>', views.get_user_profile),
    path('register_send_mail', views.register_send_mail),
    path('register_final_verify/<str:token>', views.register_final_verify),
    path('check_username_or_email', views.check_username_or_email),
    path('get_school_list_by_city', views.get_school_list_by_city),
    path('get_school/<int:id>', views.get_school),
    path('create_school', views.create_shcool),
]