FROM cybersecnatlab/socaz:python-3.11-bullseye

RUN pip install reed-solomon-ccsds

WORKDIR /app
COPY satellite.py /app/satellite.py

CMD socaz --timeout 240 --flag-from-env FLAG --bind 1337 --cmd "python3 satellite.py"