FROM debian:latest

RUN apt update
RUN apt install -y socat build-essential
RUN apt upgrade -y

WORKDIR /root
EXPOSE 9696/tcp

COPY ./pwn_2 /root/pwn_2
COPY ./sources/flag.txt /root/flag.txt

CMD ["/usr/bin/socat", "TCP-LISTEN:9696,reuseaddr,fork", "EXEC:/root/pwn_2"]
