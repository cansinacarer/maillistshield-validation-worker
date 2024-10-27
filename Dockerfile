FROM python:3.10-slim
LABEL maintainer="Cansin Acarer https://cacarer.com"

# Update package list and install whois and other dependencies
RUN apt-get -y update && \
    apt-get install --no-install-recommends -y whois && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy the application files
ADD . /my-app
WORKDIR /my-app

# Install the requirements
RUN pip install -r requirements.txt

# Expose the port
EXPOSE 5000

# Make sure the messages reach the console
ENV PYTHONUNBUFFERED=1

# Run the application
CMD ["gunicorn","-b", "0.0.0.0:5000", "-w", "2", "-k", "gevent", "--worker-tmp-dir", "/dev/shm", "run:app", "--timeout", "1000"]