FROM ubuntu:18.04

RUN apt-get update
RUN apt install libuv1

COPY . /app
WORKDIR /app
EXPOSE 12345

RUN chmod +x ./server
CMD ["./server"]
