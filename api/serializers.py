from rest_framework import serializers
from . import models

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.User
        fields = ['username', 'email', 'name', 'surname', 'patronymic']


class SchoolSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.User
        fields = ['name']


class SchoolClassSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.User
        fields = ['letter', 'number']