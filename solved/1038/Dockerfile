FROM sagemath/sagemath:9.0

USER root
RUN apt-get update && apt-get install socat -y

WORKDIR /app
COPY /deploy/chal.sage /app/
COPY /deploy/flag /app/
RUN chmod -R 777 /app

USER sage

EXPOSE 24680

CMD "socat \"TCP-LISTEN:24680,reuseaddr,fork\" \"EXEC:sage chal.sage,nofork,stderr\""
