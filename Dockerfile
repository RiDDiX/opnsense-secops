FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    iputils-ping \
    net-tools \
    dnsutils \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY config/ ./config-defaults/

RUN mkdir -p /app/reports /app/config \
    && groupadd -g 10001 secops \
    && useradd -u 10001 -g secops -s /usr/sbin/nologin -m -d /home/secops secops \
    && chown -R secops:secops /app /home/secops

COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# nmap raw socket use needs CAP_NET_RAW; the container caps grant it without root.
USER secops

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:5000/api/health || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "120", "src.web.app:app"]
