FROM debian:latest

RUN apt update
RUN apt install -y socat build-essential
RUN apt upgrade -y

WORKDIR /root
EXPOSE 6969/tcp

COPY ./pwn_1 /root/pwn_1
COPY ./sources/flag.txt /root/flag.txt

CMD ["/usr/bin/socat", "TCP-LISTEN:6969,reuseaddr,fork", "EXEC:/root/pwn_1"]
