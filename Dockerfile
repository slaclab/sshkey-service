FROM python:3.9

WORKDIR /app

COPY ./requirements.txt /code/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt

COPY ./ /app

CMD ["fastapi", "run", "/app/app.py", "--port", "8000"]
