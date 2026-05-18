FROM python:3.12-slim-bookworm@sha256:123be5684f39d8476e64f47a5fddf38f5e9d839baff5c023c815ae5bdfae0df7

ENV USER chall

USER root
RUN apt-get update && apt-get install -y socat
RUN adduser -u 1337 $USER

USER $USER
WORKDIR /app
COPY ./deploy/chal.py /app
COPY ./deploy/flag /app
COPY ./deploy/main /app

EXPOSE 5000

CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:python3 chal.py,nofork,stderr"]