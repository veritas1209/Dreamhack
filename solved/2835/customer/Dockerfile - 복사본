FROM ubuntu:24.04

ENV USER customer

USER root

WORKDIR /home/customer

RUN apt-get update && apt-get install -y curl netcat-openbsd
RUN useradd -u 1337 $USER

COPY action.sh .
COPY flag.txt . 

RUN chown $USER:$USER /home/customer/action.sh /home/customer/flag.txt
RUN chmod 0500 /home/customer/action.sh
RUN chmod 0400 /home/customer/flag.txt

USER $USER

CMD ["./action.sh"]