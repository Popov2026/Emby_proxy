FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY emby_proxy.py .

# Reglages, cache et journal dans un volume : ils survivent aux mises a jour.
ENV EMBY_PROXY_CONFIG=/data/emby_proxy.ini \
    EMBY_PROXY_CACHE_DIR=/data/cache_images \
    EMBY_PROXY_LOG_FILE=/data/emby_proxy.log \
    EMBY_PROXY_ACTIVITY_LOG=/data/emby_activity.log \
    EMBY_PROXY_SECURITY_LOG=/data/emby_security.log \
    PYTHONUNBUFFERED=1
VOLUME /data

EXPOSE 8097 8098
CMD ["python", "emby_proxy.py"]
