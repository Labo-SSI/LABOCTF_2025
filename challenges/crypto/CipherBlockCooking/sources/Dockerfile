FROM debian:12-slim

RUN apt update -y && apt install -y python3 socat python3-pip
RUN python3 -m pip install pycryptodome --break-system-packages

COPY . /app

WORKDIR /app

CMD [ "bash", "/app/socat-wrapper.sh" ]
