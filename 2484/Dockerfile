FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY flag.txt /tmp/flag.txt
RUN RANDOM_NAME=$(head -c 1000 /dev/urandom | tr -dc 'a-z0-9' | head -c 32) && \
    mv /tmp/flag.txt /flag_${RANDOM_NAME}.txt

COPY app/ .

EXPOSE 8080

CMD ["python", "app.py"]
