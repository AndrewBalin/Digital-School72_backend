from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from rest_framework.views import APIView
from rest.framework.parsers import JSONParser
from ds72.decorators import login_jwt_required
from datetime import datetime, timedelta
import jwt

from ds72.settings import (
    SECRET_KEY, 
    FERNET_ENCODE_KEY, 
    EMAIL_HOST_USER,
)
from ds72.fernet import *
from api.models import SchoolClass, User
from api.serializers import SchoolClassSerializer, UserSerializer


@login_jwt_required
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
            try:
                user = User.objects.get(email=username)
            except user.DoesNotExist:
                return JsonResponse('wrong data', status=404, safe=False)
        else:
            try:
                user = User.objects.get(username=username)
            except user.DoesNotExist:
                return JsonResponse('wrong data', status=404, safe=False)
            
        if check_password(password, user.password):
            dt = datetime.now() + timedelta(days=30)
            res = JsonResponse(user.pk, safe=False)
            res.set_cookie(
                key="utoken",
                value=fernet_msg_encode(user.token),
                expires=int(dt.strftime('%s')),
            )
            user.is_active = True
            user.save()
            return res
        else:
            return JsonResponse("wrong data", status=404, safe=False)