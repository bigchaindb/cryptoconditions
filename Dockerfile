FROM python:3

RUN apt-get update && apt-get install -y vim

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

RUN pip install --upgrade pip
RUN pip install poetry

COPY ./codecov.yml /usr/src/app/codecov.yml
COPY ./docs /usr/src/app/docs
COPY ./Makefile /usr/src/app/Makefile
COPY ./media /usr/src/app/media
COPY ./planetmint-cryptoconditions /usr/src/app/planetmint-cryptoconditions
COPY ./planetmint_cryptoconditions /usr/src/app/planetmint_cryptoconditions
COPY ./poetry.lock /usr/src/app/poetry.lock
COPY ./pyproject.toml /usr/src/app/pyproject.toml
COPY ./pytest.ini /usr/src/app/pytest.ini
COPY ./README.rst /usr/src/app/README.rst
COPY ./tests /usr/src/app/tests
COPY ./tox.ini /usr/src/app/tox.ini

RUN poetry config virtualenvs.create false
RUN poetry install --no-root

RUN adduser --system --group nonroot
USER nonroot
