FROM python:3.10-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

RUN apt-get update && \
    apt-get install -y socat && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m crypto
WORKDIR /home/crypto

COPY server.py .
COPY entrypoint.sh .
RUN echo "DH{This_is_fake_flag}" > flag.txt

RUN chown -R root:crypto /home/crypto && \
    chmod 755 /home/crypto && \
    chmod 755 /home/crypto/entrypoint.sh && \
    chmod 750 /home/crypto/server.py && \
    chmod 440 /home/crypto/flag.txt

EXPOSE 8000

USER crypto
ENTRYPOINT ["/home/crypto/entrypoint.sh"]
