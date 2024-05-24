FROM fukamachi/sbcl:2.4.1-alpine

RUN apk add build-base libev \
 && ros install clack

COPY . /root/.roswell/lisp/quicklisp/local-projects/app
RUN sbcl --non-interactive  --eval "(ql:quickload '(:app :woo))"

ENV FLAG="openECSC{example_flag_~8,'0X}"

ENTRYPOINT []
CMD ["clackup", "--server", ":woo", "--address", "0.0.0.0", "--port", "8080", "/root/.roswell/lisp/quicklisp/local-projects/app/app.lisp"]
