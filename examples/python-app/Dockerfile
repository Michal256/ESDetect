FROM python:3.9-slim
WORKDIR /app
COPY ./app /app
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 8080
RUN useradd appuser && chown -R appuser:appuser /app && chmod -R o-r /app && apt-get update -y && apt-get install curl -y
USER appuser
ENTRYPOINT ["python", "server.py"]
