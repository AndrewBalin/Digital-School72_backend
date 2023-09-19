from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.core.mail import send_mail
from rest_framework.views import APIView
from rest_framework.parsers import JSONParser
from ds72.decorators import login_jwt_required
from datetime import datetime, timedelta
import django.middleware.csrf as csrf
import jwt

from ds72.settings import (
    SECRET_KEY, 
    FERNET_ENCODE_KEY, 
    EMAIL_HOST_USER,
)
from ds72.fernet import *
from api.models import SchoolClass, User
from api.serializers import SchoolClassSerializer, UserSerializer

def jwt_verify_encode(username: str, email: str, password: str) -> str:
    dt = datetime.now() + timedelta(days=30)
    payload = {
        'email': str(email),
        'username': str(username),
        'password': str(password),
        'exp': dt
    }

    token = jwt.encode(
        payload,
        SECRET_KEY,
        algorithm='HS256'
    )

    return token

@login_jwt_required
def get_class_data(request, id):
    try:
        schoolclass = SchoolClass.objects.get(id=id)
    except SchoolClass.DoesNotExist:
        return HttpResponse(status=404)

    if request.method == 'GET':
        serializer = SchoolClassSerializer(schoolclass)
        return JsonResponse(serializer.data)

def login(request):
    if request.method == 'GET':
        data = JSONParser().parse(request)
        username = data["email"] #need to test it !!
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
            res = JsonResponse(fernet_msg_encode(user.token), safe=False)
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
        

def register_send_mail(request):
    if request.method == 'POST':
        data = JSONParser().parse(request)
        serializer = UserSerializer(data=data)
        try:
            exist_email = User.objects.get(email=serializer.data['email'])
            exist_user = User.objects.get(username=serializer.data['username'])
            return JsonResponse("this user already exist")
        
        except exist_email.DoesNotExist or exist_user.DoesNotExist:  # TODO мне кажется здесь надо User.DoesNotExist
            if serializer.is_valid():
                token = login_jwt_required(
                    username=serializer.data['username'],
                    email=serializer.data['email'],
                    password=serializer.data['password']
                )

                try: #rewrite auth url redirect
                    send_mail(
                        'email verification',
                        f'click to verify email http://127.0.0.1:8000/authc/verify/{token}',
                        EMAIL_HOST_USER,
                        [serializer.data['email']],
                    )
                    return  JsonResponse('message was succ send', safe=False)
                
                except:
                    JsonResponse('oops, an occured error', status=500, safe=False)

            return JsonResponse(serializer.errors, status=400)

def register_final_verify(request, token):
    if request.method == 'GET':
        try:
            decrypted_token = fernet_msg_decode(token)
            decoded_data = jwt.decode(decrypted_token, SECRET_KEY, algorithms=['HS256'])

            try:
                exist_email = User.objects.get(email=decoded_data['email'])
                exist_username = User.objects.get(username=decoded_data['email'])
                return JsonResponse('user already exist', status=400, safe=False)
            
            except exist_email.DoesNotExist or exist_username.DoesNotExist:
                pass # make token and set it in cookie, return some response


        except jwt.ExpiredSignatureError:
            return JsonResponse('verify token timed out', status=400, safe=False)

        except:
            return JsonResponse('oops, an occured error', status=500, safe=False)


def get_csrf_token_view(request):
    return HttpResponse(csrf.get_token(request))