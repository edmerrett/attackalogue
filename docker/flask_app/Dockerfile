FROM python:3.12-rc

ENV ENV PIP_DEFAULT_TIMEOUT=100 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    POETRY_VERSION=1.4.1


WORKDIR /app
COPY poetry.lock pyproject.toml /app/


RUN pip3 install poetry
RUN poetry config virtualenvs.create false
RUN poetry install --no-dev

COPY src/api /app/

CMD ["app.py"]
ENTRYPOINT ["python3"]
