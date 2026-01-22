FROM python:3.11-slim

RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY prob.py /app/
COPY run.sh /app/

RUN chmod +x /app/run.sh

EXPOSE 8000

CMD ["/app/run.sh"]