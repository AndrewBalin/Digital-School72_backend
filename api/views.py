from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.core.mail import send_mail
from rest_framework.views import APIView
from rest_framework.parsers import JSONParser
from ds72.decorators import login_jwt_required, is_platform_admin, is_school_admin
from django.views.decorators.csrf import csrf_exempt
from datetime import datetime, timedelta
import django.middleware.csrf as csrf
import jwt
import re

from ds72.settings import (
    SECRET_KEY,
    FERNET_ENCODE_KEY,
    EMAIL_HOST_USER,
)
from ds72.fernet import *
from api.models import SchoolClass, User, School, City
from api.serializers import SchoolClassSerializer, UserSerializer

DATETIME_COOKIE_FORMAT = '%a, %d %b %Y %H:%M:%S GMT'

TOKEN_EXPIRY_TIME_DAYS = 30

def get_jwt_expiry_date():
    return datetime.now() + timedelta(days=TOKEN_EXPIRY_TIME_DAYS)

def jwt_verify_encode(username: str, email: str, password: str) -> str:
    dt = datetime.now() + timedelta(days=1)
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

@csrf_exempt
def login(request): # Андрей: седелал изменения в функции #need to test it !!
    if request.method == 'POST':  # <- `get` to `post`
        data = JSONParser().parse(request)
        username = data["username"]  # <- `email` to `username`
        password = data["password"]
        dt = get_jwt_expiry_date()  # when the token will expire
        user = None
        # check if login by email
        if re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', username) is not None:
            try:
                user = User.objects.get(email=username)
            except:
                return JsonResponse('wrong login data', status=400, safe=False)
        else:
            try:
                user = User.objects.get(username=username)
            except:
                return JsonResponse('wrong login data', status=404, safe=False)

        if check_password(password, user.password):
            res = JsonResponse(fernet_msg_encode(user.token), safe=False)
            res.set_cookie(
                key="utoken",
                value=fernet_msg_encode(user.token),
                expires=int(dt.strftime(DATETIME_COOKIE_FORMAT)),
            )
            user.is_active = True
            user.save()
            return res
        else:
            return JsonResponse("wrong login data", status=400, safe=False)
        

@csrf_exempt
def register_send_mail(request):
    if request.method == 'POST':
        data = JSONParser().parse(request)
        serializer = UserSerializer(data=data)
        try:
            exist_email = User.objects.get(email=data['email'])
            exist_user = User.objects.get(username=data['username'])
            return JsonResponse("this user already exist")
        
        except:  # TODO мне кажется здесь надо User.DoesNotExist
            if serializer.is_valid():
                token = jwt_verify_encode(
                    username=serializer.data['username'],
                    email=serializer.data['email'],
                    password=data['password']
                )

                try:  # TODO: rewrite auth url redirect
                    send_mail(
                        'email verification',
                        f'click to verify email http://digital-school72.ru/email_confirm?token={token} or http://localhost:3000/email_confirm?token={token} (dev version)',
                        EMAIL_HOST_USER,
                        [serializer.data['email']],
                    )
                    return JsonResponse('message was succ send', safe=False)

                except:
                    JsonResponse('oops, an occured error', status=500, safe=False)

            return JsonResponse(serializer.errors, status=400)

def register_final_verify(request, token):
    if request.method == 'GET':
        JWT_LOGIN_DT = get_jwt_expiry_date()
        decoded_data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        try:
            print('flag on check is exists')
            exist_email = User.objects.get(email=decoded_data['email'])
            exist_username = User.objects.get(username=decoded_data['email'])
            return JsonResponse('user already exist', status=400, safe=False)
        
        except:

            # make token and set it in cookie, return some response
            new_user = User.objects.create_user(
                username=decoded_data['username'],
                email=decoded_data['email'],
                password=decoded_data['password'],
                surname='',
                patronymic='',
                role='0'
            )
            res = JsonResponse(f"{new_user.pk}")
            res.set_cookie(
                key='utoken',
                value=fernet_msg_encode(new_user.token),
                expires=int(JWT_LOGIN_DT.strftime(DATETIME_COOKIE_FORMAT)),
            )

            new_user.is_active = True
            new_user.save()

            return res

        # except jwt.ExpiredSignatureError:
        #     return JsonResponse('verify token timed out', status=401, safe=False)

        # except Exception as e:
        #     print(e)
        #     return JsonResponse(f'oops, an occured error {e}', status=500, safe=False)

@login_jwt_required
def get_user_profile(request, id):  # TODO: проверка на права доступа (может ли пользователь выполнить действие)
    if request.method == "GET":
        try:
            user = User.objects.get(pk=id)
            serializer = UserSerializer(user)
            return JsonResponse(serializer.data)

        except:
            return JsonResponse('user does not exist', safe=False, status=404)

@login_jwt_required
def get_user_name(request, id):  # TODO: проверка на права доступа (может ли пользователь выполнить действие)
    if request.method == "GET":
        try:
            user = User.objects.get(pk=id)
            data = {
                "id": f"{user.pk}",
                "username": user.username,
                "name": user.name,
                "surname": user.surname,
                "patronymic": user.patronymic,
                "role": user.role
            }

            return JsonResponse(data, safe=False)

        except:
            return JsonResponse('user does not exist', status=404, safe=False)

@login_jwt_required
def get_user_email(request, id):  # TODO: проверка на права доступа (может ли пользователь выполнить действие)
    if request.method == "GET":
        try:
            user = User.objects.get(pk=id)
            serializer = UserSerializer(user)

            return JsonResponse(serializer.data["email"], safe=False)

        except:
            return JsonResponse('user does not exist', status=404, safe=False)

@login_jwt_required
def add_class(request):  # TODO: проверка на права доступа (может ли пользователь выполнить действие)
    if request.method == "POST":
        try:
            post = request.POST
            teacher_id = post['teacher_id']
            number = post['number']
            letter = post['letter']
            teacher = User.objects.get(id=teacher_id)
            SchoolClass(teacher=teacher, letter=letter, number=number) # TODO определять из какой школы класс
            return JsonResponse('success', status=200, safe=False)
        except User.DoesNotExist:
            return JsonResponse('teacher does not exit', status=404, safe=False)

@login_jwt_required
def add_student_to_class(request):  # TODO: проверка на права доступа (может ли пользователь выполнить действие)
    if request.method == "POST":
        try:
            post = request.POST
            class_id = post['class_id']
            student_id = post['student_id']
            school_class = SchoolClass.objects.get(id=class_id)
            student = User.objects.get(id=student_id)
            student.classes.add(school_class)
            return JsonResponse('success', status=200, safe=False)
        except SchoolClass.DoesNotExist:
            return JsonResponse('teacher does not exit', status=404, safe=False)

@csrf_exempt
def get_cities(request):
    res = []
    for i in City.objects.all():
        res.append(i.name)
    return JsonResponse(res, status=200, safe=False)  # TODO: ПРОВЕРИТЬ

@csrf_exempt
@login_jwt_required
def add_city(request):  # TODO: проверка на права доступа (может ли пользователь выполнить действие)
    if request.method == 'POST':
        name = request.POST['name']
        City(name=name)
        return JsonResponse('success', status=200)

def get_csrf_token_view(request):
    return HttpResponse(csrf.get_token(request))

# @csrf_exempt
# @is_school_admin
# def create_class(request):
#     if request.method == "POST":
#         try:
#             user = User.objects.get(pk=id)
#             if user.role == "teacher":
#                 data = JSONParser().parse(request)

#         except:
#             pass

@csrf_exempt
@is_platform_admin
def create_shcool(request):
    if request.method == "POST":
        data = JSONParser().parse(request)
        try:
            school = School.objects.get(name=data["name"])
            return JsonResponse('school already exists', status=403, safe=False)
        except:
            try:
                city = City.objects.create(name=data["city"])
            except:
                city = City.objects.get(name=data["city"])
            new_school = School.objects.create(name=data["name"], city=city)
            return JsonResponse(f"{new_school.id}", safe=False)

def get_school(request, id):
    if request.method == "GET":
        try:
            school = School.objects.get(pk=id)
            data = {"id": school.id, "name": school.name, "city": school.city.name}
            return JsonResponse(data, safe=False)
        except:
            return JsonResponse("school does not exists", status=404, safe=False)

@csrf_exempt
def get_school_list_by_city(request):
    if request.method == "POST":
        data = JSONParser().parse(request)
        try:
            schools = School.objects.filter(city_name=data["city"])
            res = []
            for i in schools:
                res.append(i.name)
            return JsonResponse(res, safe=False)
        except:
            return JsonResponse("no one schools detected with this city", safe=False, status=404)

@csrf_exempt
def check_username_or_email(request):
    if request.method == "POST":
        data = JSONParser().parse(request)
        if "@" in data["username"]:
            try:
                user = User.objects.get(email=data["username"])
                return JsonResponse("user detected with this email", safe=False)
            except:
                return JsonResponse("no one user detected with this email", safe=False, status=404)
        else:
            try:
                user = User.objects.get(username=data["username"])
                return JsonResponse("user detected with this username", safe=False)
            except:
                return JsonResponse("no one user detected with this username", safe=False, status=404)

def test_make_city_school(request):
    if request.method == "GET":
        new_city = City.objects.create(name="тюмень")
        new_school = School.objects.create(name="Digital School 72", city_name=new_city.name)
        return JsonResponse('succ', safe=False)