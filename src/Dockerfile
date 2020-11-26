FROM python:3.8.6-slim-buster

# Install the needed tools.
RUN bash -c 'for i in {1..8}; do mkdir -p "/usr/share/man/man$i"; done' && \
    apt update && apt install --no-install-recommends -y git

# Copy requirements and install.
COPY ./requirements.txt /motan/
RUN python3 -m pip install --no-cache-dir -r /motan/requirements.txt

# Copy the needed files.
COPY ./motan/ /motan/motan/

# Set the working directory (to be used when mounting files from the host).
WORKDIR /workdir
VOLUME /workidr

# Set the entrypoint to motan command line interface.
ENV PYTHONPATH="/motan"

ENTRYPOINT ["python3", "-m", "motan.cli"]
