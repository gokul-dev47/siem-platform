FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir redis requests
COPY log_generator.py .
CMD ["python", "-u", "log_generator.py"]
