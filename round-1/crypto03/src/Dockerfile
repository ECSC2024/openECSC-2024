FROM cybersecnatlab/socaz:python-3.11-alpine

COPY ./requirements.txt ./
RUN pip install -r requirements.txt

COPY ./stealing-seeds.py /home/user/stealing-seeds

CMD socaz --timeout 300 --flag-from-env FLAG --bind 1337 --cmd /home/user/stealing-seeds