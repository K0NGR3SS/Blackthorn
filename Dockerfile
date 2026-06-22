# WAFPierce CLI image (headless; no GUI/PySide6).
#   docker build -t wafpierce .
#   docker run --rm wafpierce scan https://target --safe-mode
#   docker run --rm wafpierce doctor
FROM python:3.13-slim

# curl_cffi ships a bundled libcurl-impersonate; no system curl build needed.
WORKDIR /app

# Install deps first for better layer caching.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Now the full source + editable install (gives the `wafpierce` entrypoint).
COPY . .
RUN pip install --no-cache-dir -e .

# Drop privileges.
RUN useradd --create-home --uid 10001 pierce
USER pierce

ENTRYPOINT ["wafpierce"]
CMD ["--help"]
