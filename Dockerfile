FROM python:3.10.13-bookworm

WORKDIR /app

COPY . /app

RUN pip install -r requirements.txt

EXPOSE 80

CMD ["python", "app.py"]
