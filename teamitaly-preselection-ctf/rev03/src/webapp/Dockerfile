FROM python:3.12.4

COPY ./requirements.txt .
RUN pip install --no-cache-dir --upgrade -r requirements.txt

COPY ./templates templates
COPY ./static static

RUN rm static/script.js

COPY ./server.py app.py

CMD ["python3", "app.py"]