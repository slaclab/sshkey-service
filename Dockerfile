FROM python:3.11-slim

WORKDIR /app

COPY ./requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt

COPY ./ /app

# Create directory for blacklist file
RUN mkdir -p /etc/sshkey-service && \
    touch /etc/sshkey-service/blacklist.txt && \
    chmod 644 /etc/sshkey-service/blacklist.txt

#CMD ["fastapi", "run", "/app/app.py", "--port", "8000"]
