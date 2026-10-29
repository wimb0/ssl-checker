FROM alpine:3.21

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DATA_DIR=/data \
    PORT=3082

# python3 and cryptography come from the Alpine repository: available for amd64 and arm64,
# nothing needs to be compiled and pip is not required.
# tzdata: so that TZ=Europe/Amsterdam (etc.) is applied to the times in alarm emails.
RUN apk add --no-cache python3 py3-cryptography tzdata \
 && addgroup -S -g 10001 app \
 && adduser -S -u 10001 -G app -h /app app \
 && mkdir /data && chown app:app /data

WORKDIR /app
COPY server.py .
COPY public ./public

USER app
VOLUME /data
EXPOSE 3082

# Generous timeout: a Raspberry Pi Zero 2 W starts Python noticeably slower
HEALTHCHECK --interval=60s --timeout=10s --start-period=20s --retries=3 \
  CMD python3 -c "import urllib.request as u; u.urlopen('http://127.0.0.1:3082/healthz', timeout=5)" || exit 1

CMD ["python3", "server.py"]
