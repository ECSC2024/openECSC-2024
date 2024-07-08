FROM cybersecnatlab/socaz:ubuntu-jammy

RUN apt update && apt install -y libgmp-dev python3.11-dev python3-pip 
COPY ./requirements.txt ./
RUN pip install -r requirements.txt

COPY ./chall.py /home/user/chall
RUN chmod +x /home/user/chall

CMD socaz --timeout 30 --flag-from-env FLAG --bind 1337 --cmd /home/user/chall