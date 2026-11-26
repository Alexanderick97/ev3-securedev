FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py init_db.py ./
EXPOSE 5000
CMD ["sh", "-c", "python init_db.py || true; flask --app app run --host=0.0.0.0 --port=5000"]
