FROM python:3.14-alpine3.23
RUN apk add --no-cache iproute2 socat
COPY api.py /test/api.py
COPY netbird /usr/local/bin/netbird
RUN chmod +x /usr/local/bin/netbird
CMD ["python3", "/test/api.py"]
