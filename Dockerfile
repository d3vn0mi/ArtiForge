FROM python:3.12-slim

WORKDIR /app

# Install Python dependencies first (layer cached unless requirements change)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the package and install it (non-editable so labs land in site-packages)
COPY setup.py README.md ./
COPY cli.py ./
COPY artiforge/ ./artiforge/
RUN pip install --no-cache-dir .

# /work is the user-facing mount point:
#   docker run --rm -v "$(pwd):/work" artiforge generate --lab uc3
# Artifacts default to ./artifacts which resolves to /work/artifacts on the host.
WORKDIR /work

ENTRYPOINT ["artiforge"]
CMD ["--help"]
