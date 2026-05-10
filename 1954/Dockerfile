FROM python:3.10-alpine@sha256:930b4f931ab35253e85b21e812c345c0a091ca702fc45d90c1c45264f90b43c3

ENV USER=chall
ENV PORT=31337

# Install package
RUN apk add socat

# Add user
RUN adduser -D -g "" -u 1337 $USER

# Add files
COPY --chown=root:root ./deploy/chall.py /home/$USER/chall.py
COPY --chown=root:root ./deploy/run.sh /home/$USER/run.sh
COPY --chown=root:root ./deploy/flag /home/$USER/flag

WORKDIR /home/$USER
RUN chmod 705 run.sh

USER $USER
EXPOSE $PORT

CMD ["socat", "TCP-LISTEN:31337,reuseaddr,fork", "EXEC:./run.sh,stderr"]
