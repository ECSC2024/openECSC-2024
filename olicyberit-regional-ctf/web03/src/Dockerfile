FROM python:3.11-alpine

RUN apk update && apk upgrade && apk add dumb-init
RUN addgroup -S web && adduser -S web

WORKDIR /app
COPY requirements.txt .

RUN pip install -r requirements.txt

COPY src .
RUN chown -R web:web .

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app", "--user", "web", "--group", "web", "-w", "4"]