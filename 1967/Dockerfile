FROM ubuntu:22.04@sha256:b6b83d3c331794420340093eb706a6f152d9c1fa51b262d9bf34594887c2c7ac

ENV USER chall

RUN apt-get update && apt-get install -y socat
RUN adduser -u 1337 --disabled-password --gecos "" $USER
RUN mkdir /app && chown $USER:$USER /app

USER $USER

WORKDIR /app
COPY --chown=$USER:$USER ./deploy/main /app
RUN chmod 755 /app/main
COPY --chown=$USER:$USER ./deploy/flag /app 

EXPOSE 5000

CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:./main,nofork,stderr"]
