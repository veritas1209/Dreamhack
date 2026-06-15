FROM python:3.11-alpine@sha256:84271da1cd297b01dd4706e01e7789b08b54a5a512c0e3fcaf11c902640f5ebd

ENV USER chall

USER root
RUN apk add socat
RUN adduser -u 1337 -D -g "" $USER
RUN pip install pycryptodome

USER $USER
WORKDIR /app
COPY ./deploy/chal.py /app
COPY ./deploy/flag /app

EXPOSE 5000

CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:python3 chal.py,nofork,stderr"]