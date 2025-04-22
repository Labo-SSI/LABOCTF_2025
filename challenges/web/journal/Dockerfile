FROM python:3.9

RUN apt update -y && apt install -y gcc vim build-essential && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN useradd -m -s /bin/bash noob

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

RUN echo "First flag: LABO{T1m3_70_B10GgGgG}" > /app/flag1.txt && echo "Final flag: LABO{0h_y0u_t0uCh_mYYYTR4l4laaa@@@}" > /root/flag2.txt && chmod 400 /root/flag2.txt

RUN chown root:root /bin/touch && chmod 6755 /bin/touch

RUN chown -R noob:noob /app && chmod 644 /app/flag1.txt

EXPOSE 5000

USER noob

CMD ["python3", "main.py"]
