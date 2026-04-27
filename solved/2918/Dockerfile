FROM ubuntu:22.04@sha256:b6b83d3c331794420340093eb706a6f152d9c1fa51b262d9bf34594887c2c7ac

RUN apt-get update && \
    apt-get install -y --no-install-recommends socat && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash ctf

COPY memoir /home/ctf/memoir

RUN echo 'DH{**fake_flag**}' > /home/ctf/flag && \
    chown root:root /home/ctf/flag /home/ctf/memoir && \
    chmod 444 /home/ctf/flag && \
    chmod 755 /home/ctf/memoir

USER ctf
WORKDIR /home/ctf
EXPOSE 31337/tcp

CMD ["socat", "TCP-LISTEN:31337,reuseaddr,fork", "EXEC:/home/ctf/memoir,stderr"]
