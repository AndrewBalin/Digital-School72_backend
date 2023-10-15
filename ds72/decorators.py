from django.shortcuts import redirect
from django.http import JsonResponse, HttpResponse
import jwt
from api.models import User

from ds72.settings import SECRET_KEY
from ds72.fernet import *


def login_jwt_required(function):
    def wraper(request, *args, **kwargs):
        try:
            token = request.COOKIES["utoken"]
            decrypt_token = fernet_msg_decode(bytes(token, 'utf-8'))
            jwt.decode(decrypt_token, SECRET_KEY, algorithms=['HS256'])
            return function(request, *args, **kwargs)
        
        except jwt.ExpiredSignatureError:
            return JsonResponse('verify token timed out', status=400, safe=False)
        
        except:
            return HttpResponse(status=404)
    
    wraper.__doc__ = function.__doc__
    wraper.__name__ = function.__name__

    return wraper

# dont use this decorator, wrong url splitting (Line 38, Col 13)
# need to rewrite (another url)
# using /car/<int:upk>/... (request.path) to get user id in url
# remember that spliting url looks like ["", ..., ""] 
def is_owner(function):
    def wraper(request, *args, **kwargs):
        try:
            token = request.COOKIES["utoken"]
            decrypted_token = fernet_msg_decode(bytes(token, 'utf-8'))
            data = jwt.decode(decrypted_token, SECRET_KEY, algorithms=['HS256'])
            upk = request.path.split('/')[2]
            if int(upk) == int(data['id']):
                return function(request, *args, **kwargs)
            
            else:
                return HttpResponse(status=404)

        except jwt.ExpiredSignatureError:
            return JsonResponse('verify token timed out', status=400, safe=False)

        except:
            return HttpResponse(status=404)

    wraper.__doc__ = function.__doc__
    wraper.__name__ = function.__name__

    return wraper


def is_platform_admin(function):
    def wraper(request, *args, **kwargs):
        try:
            token = request.COOKIES["utoken"]
            decrypted_token = fernet_msg_decode(bytes(token, 'utf-8'))
            data = jwt.decode(decrypted_token, key=SECRET_KEY, verify=True, algorithms=['HS256'])
            try:
                user = User.objects.get(pk=data['id'])
                if user.role == 'platform admin':
                    return function(request, *args, **kwargs)
                else:
                    return JsonResponse('permission denied', status=403, safe=False) 
            except:
                return JsonResponse('permission denied', status=403, safe=False)
            
        except:
            return HttpResponse(status=404)
        
    wraper.__doc__ = function.__doc__
    wraper.__name__ = function.__name__

    return wraper


def is_school_admin(function):
    def wraper(request, *args, **kwargs):
        try:
            token = request.COOKIES["utoken"]
            decrypted_token = fernet_msg_decode(bytes(token, 'utf-8'))
            data = jwt.decode(decrypted_token, key=SECRET_KEY, verify=True, algorithms=['HS256'])
            try:
                user = User.objects.get(pk=data['id'])
                if user.role == 'school admin':
                    return function(request, *args, **kwargs)
                else:
                    return JsonResponse('permission denied', status=403, safe=False) 
            except:
                return JsonResponse('permission denied', status=403, safe=False)
            
        except:
            return HttpResponse(status=404)
        
    wraper.__doc__ = function.__doc__
    wraper.__name__ = function.__name__

    return wraper