FROM python:3

RUN apt-get update && apt-get install -y vim

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

RUN pip install --upgrade pip
RUN pip install poetry

COPY . /usr/src/app/

RUN poetry config virtualenvs.create false \
    && poetry install