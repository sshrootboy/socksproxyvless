FROM teddysun/xray:latest

RUN apk add --no-cache python3

COPY gen_xray_config.py /usr/local/bin/gen_xray_config.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/gen_xray_config.py

ENTRYPOINT ["/entrypoint.sh"]
