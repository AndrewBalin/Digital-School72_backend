FROM python:3.9-alpine

# Set unbuffered output for python
ENV PYTHONUNBUFFERED 1

# Create app directory
WORKDIR /app

# Install app dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Bundle app source
COPY . .

# Add django deploy conf
ADD ./django.sh /app/django.sh

# Add perms for deploy conf
RUN chmod 777 /app/django.sh

# Expose port
EXPOSE 8000

# entrypoint to start backend
ENTRYPOINT /app/django.sh
