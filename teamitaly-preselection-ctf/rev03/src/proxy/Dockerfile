FROM ubuntu:mantic-20240530

RUN apt update && apt upgrade -y && apt autoremove && apt install -y openssl
RUN openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -days 3650 \
-nodes -keyout tls.key -out tls.crt -subj "/CN=localhost" \
-addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1"

COPY fingerproxy_linux_amd64 ./fingerproxy

RUN chmod +x ./fingerproxy

CMD ["sh", "-c", "./fingerproxy -listen-addr :8443 -forward-url http://$FWD_HOST"]
