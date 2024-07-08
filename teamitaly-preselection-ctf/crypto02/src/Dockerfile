FROM cybersecnatlab/socaz:python-3.11-alpine

COPY ./requirements.txt ./
RUN pip install -r requirements.txt

COPY ./encrypted_diary.py /home/user/chall

CMD socaz --timeout 30 --flag-from-env FLAG --bind 1337 --cmd /home/user/chall