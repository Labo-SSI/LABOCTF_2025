FROM python:3.10-slim

RUN useradd -d /home/ctf/ -m -p ctf -s /bin/bash ctf
RUN echo "ctf:ctf" | chpasswd

RUN echo "LABO{Mathi4s_w0uld_b_Pr0ud}" > /flag.txt

WORKDIR /home/ctf
COPY jail.py .
COPY run.sh .
COPY ynetd .
RUN chmod +x ./ynetd ./run.sh

USER ctf

CMD ["./ynetd", "./run.sh", "-p", "10111"]
