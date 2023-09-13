#!/bin/sh

echo "waiting db"
python manage.py waitdb
echo "waiting db"
python manage.py waitdb
echo "starting server"
python manage.py makemigrations car
python manage.py makemigrations authc
python manage.py migrate
python manage.py runserver 0.0.0.0:8000