# Use official Python 3.10 image
FROM python:3.10-slim

# Set workdir
WORKDIR /app

# Install system dependencies for building packages
RUN apt-get update && apt-get install -y \
    build-essential git curl && \
    rm -rf /var/lib/apt/lists/*

# Upgrade pip
RUN pip install --upgrade pip

# Copy project files
COPY . /app

# Install Python dependencies
RUN pip install -r requirements.txt

# Set environment variables
ENV TRANSFORMERS_CACHE=/app/.cache/huggingface
ENV PYTHONUNBUFFERED=1

# Expose port (Render assigns $PORT)
EXPOSE 8000

# Command to run FastAPI with port from environment variable
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000}"]
