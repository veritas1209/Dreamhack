FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y socat && \
    rm -rf /var/lib/apt/lists/*

RUN pip install pycryptodome

WORKDIR /app

COPY app.py /app/

EXPOSE 8000

CMD ["socat", "TCP-LISTEN:8000,reuseaddr,fork", "EXEC:'python3 app.py'"]