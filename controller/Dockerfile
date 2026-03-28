FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY rules ./rules
ENV ADG_RULES_PATH=/app/rules/example.yaml
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
