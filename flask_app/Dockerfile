FROM python:3.12-rc-slim

COPY src/api .
RUN pip install --no-cache-dir -r requirements.txt

CMD ["app.py"]
ENTRYPOINT ["python3"]