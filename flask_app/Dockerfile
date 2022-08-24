FROM python:3.11-rc-slim

WORKDIR C:\Users\edwar\Documents\attack-api\flask_app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

CMD ["app.py"]
ENTRYPOINT ["python3"]