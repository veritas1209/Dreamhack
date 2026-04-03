FROM python:3.12-alpine@sha256:b7662fc33e07f05fb2f579c3634e1e4d2e30c02553397c6c24f775cb360dbc03

ENV USER chall

USER root
RUN apk add socat
RUN adduser -D -g "" -u 1337 $USER
RUN pip install pycryptodome

WORKDIR /app
RUN chown -R $USER:$USER /app

USER $USER
COPY ./deploy/chal.py /app
COPY ./deploy/flag /app

EXPOSE 5000

CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:python3 chal.py,nofork,stderr"]