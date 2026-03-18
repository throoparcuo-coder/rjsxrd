# Документация проекта rjsxrd

## Обзор

rjsxrd - это автоматически обновляемая коллекция публичных VPN-конфигов (V2Ray / VLESS / Trojan / VMess / Reality / Shadowsocks / Hysteria2 / TUIC) для быстрого обхода блокировок.

Проект генерирует и поддерживает актуальные конфигурации, которые можно импортировать практически в любой современный VPN-клиент (v2rayNG, NekoRay, Throne, v2rayN, V2Box, v2RayTun, Hiddify и др.).

## Особенности

- **Автоматическое обновление** через GitHub Actions (раз в 2 дня в 00:00 UTC)
- **Автоматическая верификация конфигов** через Xray-core (сортировка по скорости)
- **Двухуровневая система файлов**:
  - **Raw файлы** (`/raw/`): нетестированные конфиги сразу после загрузки
  - **Verified файлы**: протестированы, отсортированы по пингу (fastest first)
- **Автоматическая фильтрация и дедупликация** конфигов
- **Разделение больших файлов** для лучшей производительности (максимум 300 конфигов на файл, 49MB лимит GitHub)
- **Поддержка различных типов протоколов**: VLESS, VMess, Trojan, Shadowsocks, ShadowsocksR, Hysteria, Hysteria2, TUIC
- **Поддержка обработки различных форматов**:
  - Обычные URL подписки
  - Base64-кодированные подписки с авто-детектом
  - YAML конфиги (Clash/Surge) с конвертацией в VPN URL
  - Ежедневно обновляемые репозитории (формат v2YYYYMMDD)
- **Комплексная фильтрация безопасности** (`has_insecure_setting()`):
  - **VMess**: проверка `insecure`, `allowInsecure`, `security=none`, `alterId > 0` (MD5 уязвимость)
  - **VLESS**: проверка `allowInsecure`, `insecure`, `security=none`, `encryption=none`
  - **Trojan**: проверка `allowInsecure`, `insecure`
  - **Shadowsocks/ShadowsocksR**: проверка слабых шифров (RC4, CFB, BF-CFB, Salsa20 и др.)
  - **TUIC**: проверка `skip-cert-verify`
  - **Общие**: проверка `verify=0`, `verify=false`, `insecure=1/true/yes/on`
- **Ручное добавление серверов** через файл `source/config/servers.txt`
- **SNI/CIDR фильтрация** для обхода мобильных белых списков:
  - **bypass/**: безопасные конфиги (security-filtered + SNI/CIDR filtered)
  - **bypass-unsecure/**: все конфиги (SNI/CIDR filtered, без security filtering)
- **Telegram прокси интеграция**:
  - Автоматический scraping из всех источников
  - Верификация и сортировка по пингу
  - Разделение на MTProto и SOCKS5
- **Конфиги, разделенные по протоколам** (в папке split-by-protocols/)
- **Файлы all.txt и all-secure.txt** в папке default/
- **Улучшенная валидация**: только строки с поддерживаемыми протоколами (vless://, vmess://, trojan:// и др.)
- **Оптимизированная производительность**:
  - Параллельная загрузка (ThreadPoolExecutor, 16 workers)
  - curl_cffi для быстрого HTTP (2-3x быстрее requests)
  - DNS кэширование с TTL (60 секунд)
  - Конкурентное тестирование (один процесс Xray на конфиг)

## Структура проекта

- `githubmirror/` - сгенерированные .txt файлы конфигов
  - `default/` - основные конфиги
    - `1.txt, 2.txt, ...` - файлы по источникам
    - `all.txt` - все уникальные конфиги
    - `all-secure.txt` - только безопасные конфиги
  - `bypass/` - безопасные конфиги для обхода SNI/CIDR
    - `raw/` - нетестированные конфиги
    - `bypass-all.txt` - все рабочие (отсортированы по пингу)
    - `bypass-1.txt, bypass-2.txt, ...` - файлы по 300 конфигов
  - `bypass-unsecure/` - все конфиги для обхода SNI/CIDR (включая небезопасные)
    - `raw/` - нетестированные конфиги
    - `bypass-unsecure-all.txt` - все рабочие (отсортированы по пингу)
    - `bypass-unsecure-1.txt, ...` - файлы по 300 конфигов
  - `split-by-protocols/` - протокол-специфичные файлы
    - `vless.txt, vless-secure.txt`
    - `vmess.txt, vmess-secure.txt`
    - `trojan.txt, trojan-secure.txt`
    - `ss.txt, ss-secure.txt`
    - `ssr.txt, ssr-secure.txt`
    - `tuic.txt, tuic-secure.txt`
    - `hysteria.txt, hysteria-secure.txt`
    - `hysteria2.txt, hysteria2-secure.txt`
    - `hy2.txt, hy2-secure.txt`
  - `tg-proxy/` - Telegram прокси
    - `all.txt` - все прокси (MTProto + SOCKS5)
    - `MTProto.txt` - только MTProto
    - `socks.txt` - только SOCKS5
- `qr-codes/` - PNG-версии конфигов для импорта по QR-коду
- `source/` - исходный код генератора
  - `main.py` - точка входа
  - `config/` - конфигурация
  - `fetchers/` - загрузка данных
  - `processors/` - обработка
  - `utils/` - утилиты
- `docs/` - документация проекта
- `.github/workflows/` - GitHub Actions для автоматического обновления