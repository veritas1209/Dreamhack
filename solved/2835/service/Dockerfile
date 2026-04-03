FROM python:3.14.2-slim

WORKDIR /app

RUN pip install flask

COPY app.py .
COPY templates ./templates
COPY static ./static

RUN mkdir uploads

EXPOSE 5000

CMD ["python","app.py"]