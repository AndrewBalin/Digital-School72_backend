#!/bin/sh

echo "waiting db"
python manage.py waitdb
echo "waiting db"
python manage.py waitdb
echo "starting server"
python manage.py makemigrations api
python manage.py migrate
gunicorn --bind 0.0.0.0 -p 8000 --workers 5 ds72.wsgi:application
