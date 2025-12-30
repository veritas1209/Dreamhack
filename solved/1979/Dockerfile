FROM python:3.12-alpine

ENV USER rootsquare

USER root
RUN apk add socat
RUN adduser -u 1337 -D -g "" $USER

WORKDIR /chall
COPY chall.py .

RUN chown $USER:$USER /chall/chall.py
RUN chmod 0500 /chall/chall.py

USER $USER

EXPOSE 5000

CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:python3 chall.py,nofork,stderr"]