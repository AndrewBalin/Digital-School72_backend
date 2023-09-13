from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from rest_framework.views import APIView

from api.models import SchoolClass, User
from api.serializers import SchoolClassSerializer, UserSerializer


# Create your views here.
def class_data(request, id):
    try:
        schoolclass = SchoolClass.objects.get(id=id)
    except SchoolClass.DoesNotExist:
        return HttpResponse(status=404)

    if request.method == 'GET':
        serializer = SchoolClassSerializer(schoolclass)
        return JsonResponse(serializer.data)

def login(request, username, password):
    if request.method == 'GET':
        user = None
        if '@' in username:
            user = get_user_model().objects.get(email=username)
        else:
            user = get_user_model().objects.get(username=username)
        if check_password(password, user.password):
            res = JsonResponse()