# Разработка и вклад

## Структура исходного кода

### source/
- `main.py` - основной исполняемый файл (содержит только main функцию, которая вызывает другие функции)
- `config/` - настройки проекта и константы:
  - `settings.py` - общие настройки проекта
  - `URLS.txt` - список URL для всех источников (секции: default, extra_bypass, yaml, telegram)
  - `servers.txt` - список ручных серверов для добавления в конфигурации
  - `whitelist-all.txt` - список доменов для фильтрации SNI обхода
  - `cidrwhitelist.txt` - список CIDR для фильтрации IP-адресов обхода
- `fetchers/` - модули загрузки конфигов:
  - `fetcher.py` - базовый модуль загрузки конфигов
  - `daily_repo_fetcher.py` - модуль загрузки конфигов из ежедневно обновляемого репозитория
  - `yaml_converter.py` - модуль конвертации YAML-конфигов в формат VPN URL
- `processors/config_processor.py` - основной модуль обработки и фильтрации конфигов (содержит всю логику обработки)
- `utils/` - вспомогательные модули:
  - `logger.py` - логирование
  - `file_utils.py` - файловые операции, включая фильтрацию insecure конфигов
  - `github_handler.py` - работа с GitHub API

## Новые функции и улучшения

- Модуль `main.py` теперь содержит только main функцию, которая вызывает другие функции из других модулей
- Весь основной код обработки перемещен в `processors/config_processor.py`
- Добавлена функция `is_valid_vpn_config_url()` в модули `utils/file_utils.py` для проверки, является ли строка действительной VPN конфигурацией по формату протокол://
- Все функции обработки конфигов теперь используют валидацию, чтобы избежать включения неподходящих строк (например, текстовых комментариев) в итоговые файлы
- Улучшена логика обработки bypass конфигов: configs из EXTRA_URLS_FOR_BYPASS теперь правильно обрабатываются отдельно от основных configs и добавляются к bypass файлам без SNI/CIDR фильтрации
- Добавлена функция `apply_sni_cidr_filter()` в `utils/file_utils.py` для унифицированной фильтрации по SNI и CIDR
- Улучшена архитектура: чистое разделение ответственности между модулями
- Добавлена поддержка ежедневно обновляемого репозитория VPN-конфигов: автоматический поиск конфигов по дате с учетом часовых поясов и поддержка base64-декодирования

## Запуск локально

```bash
git clone https://github.com/whoahaow/rjsxrd
cd rjsxrd/source
pip install -r requirements.txt
export MY_TOKEN=<GITHUB_TOKEN>  # токен с правом repo
python main.py  # конфиги появятся в ../githubmirror
```

Для локального тестирования без загрузки в GitHub используйте флаг `--dry-run`:
```bash
python main.py --dry-run
```

## Внесение изменений

1. Форкните репозиторий
2. Создайте новую ветку: `git checkout -b feature/новая-функция`
3. Внесите изменения
4. Сделайте коммит: `git commit -m 'Добавил новую функцию'`
5. Запушьте в ветку: `git push origin feature/новая-функция`
6. Создайте Pull Request

## Тестирование

Для локального тестирования используйте флаг `--dry-run`:
```bash
python main.py --dry-run
```

Это выполнит все операции, кроме загрузки в GitHub.

## Требования

- Python 3.8+
- Зависимости из `requirements.txt`

## Архитектурные принципы

- Модульность: каждый компонент выполняет одну задачу
- Тестируемость: функции должны быть легко тестируемыми
- Производительность: параллельные операции, эффективные алгоритмы
- Обработка ошибок: устойчивость к сбоям внешних сервисов

## Подробное описание ключевых функций

### `has_insecure_setting(config_line: str) -> bool` (file_utils.py)
Функция для проверки безопасности VPN-конфигураций:
- **VMess**: Проверяет JSON-конфигурацию на insecure/allowInsecure/security=none и alterId > 0 (устаревший режим)
- **VLESS**: Проверяет allowInsecure, insecure, security=none, encryption=none
- **Shadowsocks**: Парсит URL и проверяет слабые шифры (RC4, CFB режимы и др.)
- **ShadowsocksR**: Проверяет слабые шифры в SSR формате
- **TUIC**: Проверяет skip-cert-verify параметр
- **Общие**: Проверяет verify=0, insecure=1 и другие небезопасные параметры

### `download_all_configs(output_dir)` (config_processor.py)
Загружает конфиги из всех источников:
- Параллельная загрузка из URLS (default секция), URLS_EXTRA_BYPASS, URLS_YAML
- Авто-детект base64-кодированных подписок в URLS
- Загрузка из ежедневного репозитория
- Сохраняет в разные массивы: all_configs, extra_bypass_configs, numbered_configs
- Обрабатывает ошибки и продолжает работу при сбоях отдельных источников

### `create_protocol_split_files(all_configs, output_dir)` (config_processor.py)
Создает протокол-специфичные файлы:
- Разделяет конфиги по протоколам (vless, vmess, trojan, ss, ssr, tuic, hysteria, hysteria2, hy2)
- Создает secure и unsecure версии для каждого протокола
- Применяет фильтрацию безопасности к secure версиям
- Генерирует файлы в папке split-by-protocols/

### `apply_sni_cidr_filter(configs, filter_secure)` (file_utils.py)
Унифицированная фильтрация по SNI и CIDR:
- Проверяет соответствие конфигов SNI доменам из whitelist-all.txt
- Проверяет соответствие IP-адресов CIDR диапазонам из cidrwhitelist.txt
- При необходимости применяет фильтрацию безопасности
- Используется для генерации bypass конфигов

### `build_session()` (fetcher.py)
Создает HTTP сессию с улучшенной устойчивостью:
- Добавляет Chrome User-Agent для лучшей совместимости
- Устанавливает Retry адаптер с экспоненциальной задержкой
- Обрабатывает сетевые ошибки и таймауты
- Повторные попытки при сбоях подключения



## Тестирование кода

### Модульное тестирование
Для проверки функций безопасности можно создать простой тест:
```python
from utils.file_utils import has_insecure_setting

# Проверка безопасных конфигов (должны вернуть False)
secure_configs = [
    "vless://uuid@host:443?security=tls&sni=host",
    "vmess://valid_json_config_without_insecure_settings",
    "trojan://password@host:443?security=tls&sni=host"
]

for config in secure_configs:
    print(f"{config} -> {has_insecure_setting(config)}")

# Проверка небезопасных конфигов (должны вернуть True)
insecure_configs = [
    "vless://uuid@host:443?security=tls&allowInsecure=true",
    "vmess://json_with_alterId_greater_than_0",  # legacy mode
    "ss://rc4-md5:password@host:8388"  # weak cipher
]

for config in insecure_configs:
    print(f"{config} -> {has_insecure_setting(config)}")
```

### Интеграционное тестирование
Используйте `--dry-run` флаг для тестирования всего процесса без загрузки в GitHub:
```bash
python main.py --dry-run
```

## Практики разработки

- Используйте осмысленные имена переменных и функций
- Добавляйте docstrings ко всем публичным функциям
- Обрабатывайте исключения корректно
- Используйте логирование вместо print для отладки
- Тестируйте изменения с `--dry-run` перед коммитом
- Следите за производительностью при работе с большими объемами данных
- Поддерживайте обратную совместимость при внесении изменений