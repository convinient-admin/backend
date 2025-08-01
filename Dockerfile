# Use official Python image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set work directory
WORKDIR /app

# Install system dependencies (including git)
RUN apt-get update && apt-get install -y \
    git \
    gcc \
    python3-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy project
COPY . .

# Collect static files (if needed)
RUN python [manage.py](http://_vscodecontentref_/3) collectstatic --noinput

# Expose the port
EXPOSE 8000

# Command to run the application
CMD ["sh", "-c", "python manage.py migrate && exec gunicorn --bind 0.0.0.0:8000 TP254.wsgi:application"]
