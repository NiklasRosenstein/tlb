FROM python:3.14-alpine3.23
RUN apk add --no-cache iproute2 socat
COPY api.py /test/api.py
CMD ["python3", "/test/api.py"]
