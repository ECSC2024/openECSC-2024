FROM librespace/gnuradio

RUN apt update && apt install -y xxd

COPY ./build_challenge.py /build_challenge.py
COPY ./data_creator.py /data_creator.py

ENTRYPOINT ["python3", "build_challenge.py"]

CMD ["seed"]