FROM python:3.11-slim-trixie
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Used to associate the image with a source repository outside GHA
LABEL org.opencontainers.image.source=https://github.com/slaclab/sshkey-service

# This avoids needing `uv run`  or venv activation at runtime
ENV UV_PROJECT_ENVIRONMENT=/usr/local

RUN mkdir -p /app
WORKDIR /app

COPY pyproject.toml uv.lock /app/

RUN uv sync --frozen --no-install-project --no-dev

COPY . /app

RUN uv sync --frozen --no-dev

# Create directory for blacklist file
RUN mkdir -p /etc/sshkey-service && \
    touch /etc/sshkey-service/blacklist.txt && \
    chmod 644 /etc/sshkey-service/blacklist.txt

ENTRYPOINT [ "python3", "/app/app.py" ]
