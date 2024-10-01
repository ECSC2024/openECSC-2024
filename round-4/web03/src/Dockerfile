FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

# Install supervisor
RUN apt-get update && apt-get install -y supervisor && rm -rf /var/lib/apt/lists/*

# Copy the supervisor configuration file
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

COPY ./src/ .

RUN mkdir /app/data && chown -R nobody:nogroup /app/data

CMD ["supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]