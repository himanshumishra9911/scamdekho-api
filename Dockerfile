FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y \
    libzbar0 \
    libgl1-mesa-glx \
    libglib2.0-0 \
    tesseract-ocr \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN playwright install --with-deps chromium

COPY . .

# GeoLite2-City for the homepage globe. Not committed — MaxMind does not allow
# redistribution — so pull it here when a licence key is provided. Without the
# key the build still succeeds and the globe just falls back to its curated set.
ARG MAXMIND_LICENSE_KEY=""
RUN if [ -n "$MAXMIND_LICENSE_KEY" ]; then \
      echo "Fetching GeoLite2-City..." && \
      curl -fsSL -o /tmp/geolite2.tar.gz \
        "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz" && \
      mkdir -p /tmp/geoip && tar -xzf /tmp/geolite2.tar.gz -C /tmp/geoip && \
      find /tmp/geoip -name 'GeoLite2-City.mmdb' -exec cp {} /app/app/data/GeoLite2-City.mmdb \; && \
      rm -rf /tmp/geolite2.tar.gz /tmp/geoip && \
      ls -lh /app/app/data/GeoLite2-City.mmdb; \
    else \
      echo "MAXMIND_LICENSE_KEY not set - globe geo stays disabled"; \
    fi

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
