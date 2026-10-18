FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create directories
RUN mkdir -p reports static/css static/js templates/auth templates/scan

# Environment variables
ENV FLASK_APP=run.py
ENV FLASK_ENV=production
ENV SECRET_KEY=change-this-in-production-please
ENV DATABASE_URL=sqlite:///scanner.db

EXPOSE 5000

CMD ["python", "run.py"]
