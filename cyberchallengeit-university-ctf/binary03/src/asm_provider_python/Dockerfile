FROM python:3.11-slim

RUN pip3 install pwntools

COPY server.py /server.py

WORKDIR /

ENTRYPOINT ["python3", "-u", "server.py"]