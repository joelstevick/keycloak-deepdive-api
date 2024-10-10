# Use the official Python image
FROM python:3.10-slim

# Set the working directory
WORKDIR /app

# Copy requirements.txt and install dependencies
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Copy the FastAPI application
COPY main.py .

# Expose the port
EXPOSE 8200

# Command to run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8200"]

