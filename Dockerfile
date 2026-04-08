FROM python:3.12-slim AS builder

WORKDIR /build

COPY pyproject.toml ./
RUN pip install --no-cache-dir --prefix=/install .

COPY src/ ./src/

FROM python:3.12-slim

RUN groupadd --gid 1000 app && \
    useradd --uid 1000 --gid app --shell /bin/bash --create-home app

COPY --from=builder /install /usr/local
COPY --from=builder /build/src /home/app/src
COPY alembic/ /home/app/alembic/
COPY alembic.ini /home/app/

WORKDIR /home/app
USER app

EXPOSE 8000
