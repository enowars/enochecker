FROM python:3.8
LABEL maintainer="ENOFLAG <mail@enoflag.de>"

# Install python3
RUN apt-get update
RUN apt-get install -y git

# copy our files in.
WORKDIR /checker
COPY ./requirements.txt /checker/requirements.txt
RUN pip3 install -r requirements.txt
COPY . .

ENTRYPOINT [ "gunicorn", "-c", "gunicorn.conf.py", "examplechecker:app" ]
