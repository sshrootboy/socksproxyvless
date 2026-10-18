# SOCKS5-прокси через Xray

Контейнер загружает параметры из subscription URL, поднимает SOCKS5 и периодически проверяет обновления.

## Запуск

```bash
cp .env.example .env
# задайте SUBSCRIPTION_URL в .env

docker compose up -d --build
```

Прокси: `socks5://127.0.0.1:1080` (порт меняется через `SOCKS_PORT` в `.env`).

## Настройки (.env)

| Переменная | По умолчанию | Описание |
|---|---|---|
| `SUBSCRIPTION_URL` | — | Ссылка на подписку; `#Имя` выбирает сервер |
| `SUBSCRIPTION_INTERVAL` | `3600` | Проверка обновлений, сек (`0` = только при старте) |
| `SOCKS_PORT` | `1080` | Порт SOCKS5 на хосте |

## Логи

```bash
docker compose logs -f
```

- `config.json обновлён` — подписка изменилась, xray перезагружен
- `Изменений в подписке нет` — всё без изменений

Принудительная проверка: `docker compose restart`
