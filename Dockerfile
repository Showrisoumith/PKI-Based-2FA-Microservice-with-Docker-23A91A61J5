# -------------------------
# Stage 1: Builder
# -------------------------
FROM python:3.11-slim AS builder
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /build


RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*


COPY requirements.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip setuptools wheel \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# Copies local 'app' directory contents (including 'scripts') to /build/app
COPY app /build/app

# (DEV convenience) copy student_private.pem
COPY student_private.pem /build/student_private.pem

# -------------------------
# Stage 2: Runtime
# -------------------------
FROM python:3.11-slim AS runtime
ENV TZ=UTC
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app

# Install runtime system packages: cron, tzdata, ca-certificates
RUN apt-get update \
    && apt-get install -y --no-install-recommends cron tzdata ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Ensure timezone is set to UTC
RUN ln -sf /usr/share/zoneinfo/UTC /etc/localtime \
    && echo "UTC" > /etc/timezone


COPY --from=builder /opt/venv /opt/venv
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:$PATH"


# COPIES main app code (e.g., app.py) to /app/app
COPY --from=builder /build/app /app/app

# ⭐ CRITICAL FIX: Explicitly copy the 'scripts' directory to /app/scripts
# This resolves the 'No such file or directory' error for the cron script.
COPY --from=builder /build/app/scripts /app/scripts 

COPY --from=builder /build/student_private.pem /app/student_private.pem


COPY --from=builder /build/app/cron /app/cron


RUN chmod -R +x /app/cron || true


RUN mkdir -p /data /cron && chmod 0755 /data /cron
VOLUME ["/data", "/cron"]


EXPOSE 8080


COPY app/cron/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

CMD ["/usr/local/bin/entrypoint.sh"]