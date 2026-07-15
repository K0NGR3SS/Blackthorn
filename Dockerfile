# Blackthorn CLI image (headless; no GUI/PySide6).
#   docker build -t blackthorn .
#   docker run --rm blackthorn scan https://target --safe-mode
#   docker run --rm blackthorn doctor
FROM python:3.13-slim

# curl_cffi ships a bundled libcurl-impersonate; no system curl build needed.
WORKDIR /app

# Install deps first for better layer caching.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Now the full source + editable install (gives the `blackthorn` entrypoint).
COPY . .
RUN pip install --no-cache-dir -e .

# Drop privileges.
RUN useradd --create-home --uid 10001 pierce
USER pierce

ENTRYPOINT ["blackthorn"]
CMD ["--help"]
