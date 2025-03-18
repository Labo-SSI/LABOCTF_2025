FROM python:3.9

WORKDIR /app

RUN apt-get update && apt-get install -y texlive 
COPY . .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

CMD ["python3", "main.py"]
