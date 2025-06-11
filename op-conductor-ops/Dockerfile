# Use the official Python image as a base image
FROM python:3.13-slim

# Set environment variables
ENV POETRY_VERSION=1.8.4

# Install dependencies
RUN apt-get update && apt-get install -y curl

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python3 -

# Add Poetry to PATH
ENV PATH="/root/.local/bin:$PATH"

# Set the working directory
WORKDIR /app

# Copy the project files
COPY ./op-conductor-ops .

# Install project dependencies
RUN poetry install

# Command to run the application
CMD ["/bin/bash", "-c", "/app/watch-docker.sh -n $NETWORK"]