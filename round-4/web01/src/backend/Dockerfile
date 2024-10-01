FROM python:3.12

# Setup working directory
RUN mkdir -p /app
WORKDIR /app

# Setup low privileged user
RUN useradd web

# Copy all files in directory
COPY . ./

# Install dependencies
RUN python3 -m pip install -r requirements.txt

# Run web application
CMD ["gunicorn", "-c", "gunicorn.conf.py", "app:app"]