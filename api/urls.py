from django.urls import path
from api import views

urlpatterns = [
    path('schoolclass/<int:id>', views.get_class_data),
]