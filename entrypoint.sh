#!/bin/sh
set -e

CONFIG="/etc/xray/config.json"
INTERVAL="${SUBSCRIPTION_INTERVAL:-3600}"
URL="${SUBSCRIPTION_URL:-}"

fetch_config() {
    echo "Загрузка параметров подключения из подписки..."
    if ! python3 /usr/local/bin/gen_xray_config.py \
        --url "$URL" \
        --prefer vless \
        --out "${CONFIG}.new"; then
        echo "Не удалось загрузить подписку" >&2
        rm -f "${CONFIG}.new"
        return 2
    fi

    if [ ! -f "$CONFIG" ] || ! cmp -s "$CONFIG" "${CONFIG}.new"; then
        mv "${CONFIG}.new" "$CONFIG"
        echo "config.json обновлён"
        return 1
    fi

    rm -f "${CONFIG}.new"
    echo "Изменений в подписке нет"
    return 0
}

reload_xray() {
    if kill -0 "$XRAY_PID" 2>/dev/null; then
        echo "Перезагрузка xray (SIGHUP)..."
        kill -HUP "$XRAY_PID" 2>/dev/null || {
            kill "$XRAY_PID" 2>/dev/null || true
            wait "$XRAY_PID" 2>/dev/null || true
            start_xray
        }
    else
        start_xray
    fi
}

start_xray() {
    echo "Запуск xray..."
    /usr/bin/xray run -config "$CONFIG" &
    XRAY_PID=$!
}

if [ -z "$URL" ]; then
    echo "Ошибка: SUBSCRIPTION_URL не задан." >&2
    exit 1
fi

fetch_rc=0
fetch_config || fetch_rc=$?
if [ "$fetch_rc" -eq 2 ]; then
    echo "Ошибка: не удалось получить ${CONFIG} из подписки." >&2
    exit 1
fi

if [ ! -f "$CONFIG" ]; then
    echo "Ошибка: не удалось получить ${CONFIG} из подписки." >&2
    exit 1
fi

start_xray

if [ "$INTERVAL" -gt 0 ] 2>/dev/null; then
    (
        while true; do
            sleep "$INTERVAL"
            fetch_rc=0
            fetch_config || fetch_rc=$?
            if [ "$fetch_rc" -eq 1 ]; then
                reload_xray
            fi
        done
    ) &
fi

wait "$XRAY_PID"
