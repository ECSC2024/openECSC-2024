FROM cybersecnatlab/socaz@sha256:acaf0c3a5809739fe2790853cc6d4ad8a622c057f92d65f6def1340d7fa71c5d

RUN adduser user

CMD socaz -e -t 60 -u 1000 -g 1000 --flag-from-env FLAG --bind 1337 --cmd /home/user/chall
