#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
gen_xray_config.py — генератор config.json для teddysun/xray из subscription URL.

Без внешних зависимостей (только стандартная библиотека).
Поддерживает строки:
  - vless://...
  - ss://... (в т.ч. outline=1)

Фикс по запросу:
  Независимо от того, что приходит в подписке, в config.json всегда ставится:
    "fingerprint": "firefox"
  (для VLESS reality и TLS).
"""

import argparse
import base64
import json
import re
import sys
from urllib.parse import urlparse, parse_qs, unquote
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

FORCED_FINGERPRINT = "firefox"  # <-- ВАЖНО: принудительный fingerprint


def _b64pad(s: str) -> str:
    s = s.strip()
    return s + "=" * ((4 - (len(s) % 4)) % 4)


def http_get_text(url: str, timeout: int = 20) -> str:
    req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urlopen(req, timeout=timeout) as r:
            data = r.read()
            enc = None
            try:
                enc = r.headers.get_content_charset()
            except Exception:
                enc = None
            return data.decode(enc or "utf-8", errors="ignore")
    except HTTPError as e:
        raise RuntimeError(f"HTTP error {e.code}") from e
    except URLError as e:
        raise RuntimeError(f"Network error: {e.reason}") from e


def maybe_decode_subscription(text: str) -> str:
    raw = text.strip()

    # Если уже видим URI — не трогаем
    if "://" in raw:
        return raw

    compact = re.sub(r"\s+", "", raw)

    try:
        decoded = base64.b64decode(_b64pad(compact), validate=False)
        decoded_text = decoded.decode("utf-8", errors="ignore").strip()
        if "://" in decoded_text:
            return decoded_text
    except Exception:
        pass

    return raw


def _first_qs(qs: dict, key: str, default=None):
    v = qs.get(key)
    if not v:
        return default
    return v[0]


def parse_ss_uri(uri: str) -> dict:
    name = ""
    if "#" in uri:
        uri, name = uri.split("#", 1)
        name = unquote(name)

    u = urlparse(uri)
    if u.scheme.lower() != "ss":
        raise ValueError("Not ss://")

    netloc = u.netloc
    path = u.path.lstrip("/")

    method = password = host = None
    port = None

    if netloc and "@" in netloc:
        left, right = netloc.rsplit("@", 1)
        hostport = right

        if ":" in left:
            method, password = left.split(":", 1)
        else:
            decoded = base64.b64decode(_b64pad(left)).decode("utf-8", errors="ignore")
            if ":" not in decoded:
                raise ValueError("Bad ss userinfo (base64)")
            method, password = decoded.split(":", 1)

        if ":" not in hostport:
            raise ValueError("Bad ss host:port")
        host, port_s = hostport.rsplit(":", 1)
        port = int(port_s)

    if (method is None or password is None or host is None or port is None) and path:
        candidate = path

        decoded = None
        try:
            decoded = base64.b64decode(_b64pad(candidate)).decode("utf-8", errors="ignore")
        except Exception:
            decoded = None

        if decoded and "@" in decoded and ":" in decoded:
            cred, hostport = decoded.rsplit("@", 1)
            method, password = cred.split(":", 1)
            host, port_s = hostport.rsplit(":", 1)
            port = int(port_s)
        else:
            if "@" not in candidate:
                raise ValueError("Bad ss path")
            cred, hostport = candidate.rsplit("@", 1)
            if ":" not in cred or ":" not in hostport:
                raise ValueError("Bad ss path format")
            method, password = cred.split(":", 1)
            host, port_s = hostport.rsplit(":", 1)
            port = int(port_s)

    if not all([method, password, host, port]):
        raise ValueError("Cannot parse ss:// fully")

    return {
        "name": name or "ss-outbound",
        "outbound": {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [
                    {
                        "address": host,
                        "port": port,
                        "method": method,
                        "password": password,
                        "udp": True,
                    }
                ]
            },
            "tag": "proxy",
        },
    }


def parse_vless_uri(uri: str) -> dict:
    name = ""
    if "#" in uri:
        uri, name = uri.split("#", 1)
        name = unquote(name)

    u = urlparse(uri)
    if u.scheme.lower() != "vless":
        raise ValueError("Not vless://")

    uuid = u.username
    host = u.hostname
    port = u.port or 443
    if not uuid or not host:
        raise ValueError("Bad vless URI (no uuid/host)")

    qs = parse_qs(u.query)

    network = _first_qs(qs, "type", "tcp")
    security = _first_qs(qs, "security", "none")

    flow = _first_qs(qs, "flow", None)
    encryption = _first_qs(qs, "encryption", "none")

    # sni/serverName
    sni = _first_qs(qs, "sni", None) or _first_qs(qs, "serverName", None)

    # Мы всё равно не используем fp из подписки, оставлено для совместимости/читаемости:
    # fp_from_sub = _first_qs(qs, "fp", None) or _first_qs(qs, "fingerprint", None)

    alpn = qs.get("alpn", [])
    if len(alpn) == 1 and "," in alpn[0]:
        alpn = [x.strip() for x in alpn[0].split(",") if x.strip()]

    outbound = {
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": host,
                    "port": port,
                    "users": [
                        {
                            "id": uuid,
                            "encryption": encryption,
                        }
                    ],
                }
            ]
        },
        "streamSettings": {
            "network": network,
            "security": security,
        },
        "tag": "proxy",
    }

    user0 = outbound["settings"]["vnext"][0]["users"][0]
    if flow:
        user0["flow"] = flow

    if security == "reality":
        pbk = _first_qs(qs, "pbk", None) or _first_qs(qs, "publicKey", None)
        sid = _first_qs(qs, "sid", None) or _first_qs(qs, "shortId", None)
        spx = _first_qs(qs, "spx", None) or _first_qs(qs, "spiderX", None)

        if not sni or not pbk:
            raise ValueError("vless reality требует как минимум sni и pbk/publicKey")

        reality = {
            "show": False,
            "serverName": sni,
            "publicKey": pbk,

            # <-- ФИКС: всегда принудительно ставим fingerprint=firefox
            "fingerprint": FORCED_FINGERPRINT,
        }
        if sid:
            reality["shortId"] = sid
        if spx:
            reality["spiderX"] = spx

        outbound["streamSettings"]["security"] = "reality"
        outbound["streamSettings"]["realitySettings"] = reality

    elif security == "tls":
        tls = {}

        # <-- ФИКС: всегда принудительно ставим fingerprint=firefox
        tls["fingerprint"] = FORCED_FINGERPRINT

        if sni:
            tls["serverName"] = sni
        if alpn:
            tls["alpn"] = alpn

        outbound["streamSettings"]["tlsSettings"] = tls

    # Минимальная поддержка ws/grpc параметров
    if network == "ws":
        ws = {}
        path = _first_qs(qs, "path", None)
        host_header = _first_qs(qs, "host", None)
        if path:
            ws["path"] = path
        if host_header:
            ws["headers"] = {"Host": host_header}
        outbound["streamSettings"]["wsSettings"] = ws

    if network == "grpc":
        grpc = {}
        service_name = _first_qs(qs, "serviceName", None)
        if service_name:
            grpc["serviceName"] = service_name
        outbound["streamSettings"]["grpcSettings"] = grpc

    return {
        "name": name or "vless-outbound",
        "outbound": outbound,
    }


def build_xray_config(outbound_entry: dict) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "port": 1080,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "tag": "socks-inbound",
            }
        ],
        "outbounds": [
            outbound_entry["outbound"],
            {"protocol": "freedom", "tag": "direct"},
        ],
        "routing": {
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["socks-inbound"],
                    "outboundTag": "proxy",
                }
            ]
        },
    }


def main():
    ap = argparse.ArgumentParser(description="Generate Xray config.json from subscription URL (ss://, vless://).")
    ap.add_argument("--url", required=True, help="Subscription URL (имя после # используется как --name)")
    ap.add_argument("--name", default=None, help="Pick entry by name after # (substring match), e.g. PaperVPN_NL")
    ap.add_argument("--prefer", default="vless", choices=["vless", "ss"], help="Prefer protocol if multiple")
    ap.add_argument("--out", default="config.json", help="Output file (default: config.json)")
    args = ap.parse_args()

    sub_url = args.url
    if "#" in sub_url:
        sub_url, fragment = sub_url.split("#", 1)
        if not args.name and fragment:
            args.name = unquote(fragment)

    text = http_get_text(sub_url, timeout=20)
    content = maybe_decode_subscription(text)

    lines = [ln.strip() for ln in content.splitlines() if ln.strip()]
    lines = [ln for ln in lines if "://" in ln]

    parsed = []
    errors = []

    for ln in lines:
        try:
            if ln.lower().startswith("vless://"):
                parsed.append(parse_vless_uri(ln))
            elif ln.lower().startswith("ss://"):
                parsed.append(parse_ss_uri(ln))
        except Exception as e:
            errors.append((ln[:120], str(e)))

    if not parsed:
        print("Не найдено ни одной валидной vless:// или ss:// строки в подписке.", file=sys.stderr)
        if errors:
            print("Примеры ошибок парсинга:", file=sys.stderr)
            for a, b in errors[:8]:
                print(f"  - {a} ... -> {b}", file=sys.stderr)
        sys.exit(2)

    chosen = None

    if args.name:
        key = args.name.lower()
        for item in parsed:
            if key in (item["name"] or "").lower():
                chosen = item
                break

    if not chosen:
        if args.prefer == "vless":
            for item in parsed:
                if item["outbound"]["protocol"] == "vless":
                    chosen = item
                    break
        if not chosen:
            for item in parsed:
                if item["outbound"]["protocol"] == "shadowsocks":
                    chosen = item
                    break

    if not chosen:
        chosen = parsed[0]

    cfg = build_xray_config(chosen)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)

    print(f"OK: {args.out} создан из записи: {chosen['name']} ({chosen['outbound']['protocol']})")


if __name__ == "__main__":
    main()
