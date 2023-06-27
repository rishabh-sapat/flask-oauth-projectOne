# Dockerfile
FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY reqOne.txt .
RUN pip install --no-cache-dir -r reqOne.txt

# Copy the Flask app
COPY . .

# Set the Flask app environment variables
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0

# Expose the Flask app port
EXPOSE 5000

# Run the Flask app
CMD ["flask", "run"]
