# Техническая документация

## Архитектура генератора

Генератор конфигов построен с использованием модульной архитектуры с четким разделением ответственности:

### Основные модули

#### `config/` - Конфигурация
- `settings.py` - глобальные настройки, токены, URL-источники, часовые пояса
- `constants.py` - константы производительности (таймауты, батчи, конкуренция)
- `URLS.txt` - список URL для основных конфигов (секции: default, extra_bypass, yaml, telegram)
- `servers.txt` - ручные серверы для добавления
- `whitelist-all.txt` - домены для SNI фильтрации (сотни доменов: Avito, Yandex, Mail.ru, etc.)
- `cidrwhitelist.txt` - CIDR диапазоны для IP фильтрации

#### `fetchers/` - Загрузка данных
- `fetcher.py` - базовый загрузчик с curl_cffi (быстрый, обход анти-ботов)
- `daily_repo_fetcher.py` - загрузка из ежедневно обновляемых репозиториев (формат v2YYYYMMDD)
- `yaml_converter.py` - конвертер Clash/Surge YAML в VPN URL
- `telegram_proxy_scraper.py` - извлечение MTProto/SOCKS5 прокси из контента

#### `processors/` - Обработка
- `config_processor.py` - основная оркестрация пайплайна
- `telegram_proxy_processor.py` - обработка Telegram прокси

#### `utils/` - Утилиты
- `file_utils.py` - файловые операции, security filtering, SNI/CIDR фильтрация
- `logger.py` - потокобезопасное логирование
- `github_handler.py` - GitHub API взаимодействия
- `git_updater.py` - Git-коммиты (режим Actions)
- `config_verifier.py` - DNS/TCP/HTTP верификация с кэшированием
- `xray_batch_tester.py` - v2rayN-стиль Xray-core батч-тестирование
- `telegram_proxy_verifier.py` - верификация Telegram прокси

### Детали компонентов

#### Main (`main.py`)
- **Основная точка входа** в приложение
- Обрабатывает аргументы командной строки: `--dry-run`, `--skip-xray`, `--use-git`
- Вызывает `process_all_configs()` из `config_processor.py`
- Передает `output_dir`, флаги верификации и режим загрузки

#### ConfigProcessor (`processors/config_processor.py`)
**Центральный оркестратор пайплайна:**

1. **`download_all_configs()`** - Загрузка из всех источников параллельно:
   - Fetch из URLS.txt (default секция) → `all_configs`
   - Fetch из URLS.txt (extra_bypass секция) → `extra_bypass_configs`
   - Fetch из URLS.txt (yaml секция) → конвертация → VPN URLs
   - Fetch из daily-updated repos → `daily_configs`
   - Load из servers.txt → `manual_configs`
   - Scan контента на Telegram прокси → `mtproto_proxies`, `socks5_proxies`

2. **Генерация default файлов:**
   - `create_numbered_default_files()` - 1.txt, 2.txt, ... по источникам
   - `create_all_configs_file()` - all.txt (дедуплицированные)
   - `create_secure_configs_file()` - all-secure.txt (security-filtered)

3. **Генерация bypass файлов:**
   - `apply_sni_cidr_filter()` - SNI/CIDR фильтрация основных конфигов
   - Комбинирование с extra bypass (без SNI/CIDR фильтрации)
   - Дедупликация и security filtering
   - Создание raw файлов (`bypass-all-raw.txt`, `bypass-unsecure-all-raw.txt`)
   - `_verify_config_file()` - верификация через Xray-core
   - Сортировка по пингу и создание финальных файлов

4. **Разделение по протоколам:**
   - Классификация по протоколу (vless, vmess, trojan, ss, ssr, tuic, hysteria, hy2)
   - Создание secure/unsecure вариантов каждого
   - Параллельная запись файлов через ThreadPoolExecutor

5. **Обработка Telegram прокси:**
   - Мердж scraped + manual прокси
   - Верификация через `telegram_proxy_verifier.py`
   - Сортировка по латентности
   - Создание all.txt, MTProto.txt, socks.txt

#### XrayBatchTester (`utils/xray_batch_tester.py`)
**v2rayN-стиль батч-тестирование:**

- **Один процесс Xray** с множеством inbound/outbound (100 конфигов на батч)
- **Динамическое выделение портов** (диапазон 5000 портов)
- **Платформенная оптимизация**:
  - Linux/WSL: async + curl_cffi AsyncSession
  - Windows: ThreadPoolExecutor + sync requests
- **Пайплайн тестирование**:
  1. Старт Xray в thread pool (не блокирует event loop)
  2. HTTP тест через curl_cffi async (native async)
  3. Cleanup Xray в фоне
- **Fallback механизмы**: TCP + TLS handshake когда Xray падает
- **Кэширование ошибок** для дебаггинга

#### ConfigVerifier (`utils/config_verifier.py`)
**Высокопроизводительная DNS/TCP/HTTP верификация:**

- `_extract_host_port()` - парсинг VPN URLs для получения host:port
- `_resolve_host()` - DNS резолюция с кэшированием (aiodns + socket fallback)
- `_tcp_ping()` - TCP connectivity test (0.5s быстрый таймаут)
- `_http_proxy_ping()` - HTTP запрос ЧЕРЕЗ прокси (v2rayN-стиль)
- `verify_configs()` - многопоточная батч верификация
- `verify_configs_two_pass()` - быстрый фильтр + полная верификация

#### File Utilities (`utils/file_utils.py`)
**Критические функции:**

- `has_insecure_setting()` - комплексная проверка безопасности:
  - **VMess**: `insecure`, `allowInsecure`, `security=none`, `alterId > 0` (MD5 уязвимость)
  - **VLESS**: `allowInsecure`, `insecure`, `security=none`, `encryption=none`
  - **Trojan**: `allowInsecure`, `insecure`
  - **Shadowsocks**: слабые шифры (RC4, CFB, BF-CFB, Salsa20 и др.)
  - **ShadowsocksR**: парсинг SSR формата, проверка шифров
  - **TUIC**: `skip-cert-verify`
  - **Общие**: `verify=0`, `verify=false`, `insecure=1/true/yes/on`

- `apply_sni_cidr_filter()` - унифицированная SNI/CIDR фильтрация:
  - Загрузка доменов из `whitelist-all.txt`
  - Загрузка CIDR из `cidrwhitelist.txt`
  - Извлечение host/port из конфига
  - Проверка на совпадение с whitelist

- `deduplicate_configs()` - удаление дублей по host:port
- `prepare_config_content()` - нормализация, разделение склеенных конфигов
- `is_valid_vpn_config_url()` - валидация формата `protocol://`

#### GitHub Handler (`utils/github_handler.py`)
**Управление загрузкой в GitHub:**

- PyGithub библиотека для API взаимодействий
- Обработка конфликтов SHA с экспоненциальной задержкой
- Сравнение содержимого для избежания лишних коммитов
- Проверка лимитов GitHub API
- Параллельная загрузка через ThreadPoolExecutor

#### Git Updater (`utils/git_updater.py`)
**Git-коммиты для режима Actions:**

- Использует git команды вместо API
- Автоматический commit + push изменений
- Обработка merge conflicts
- Оптимизировано для GitHub Actions среды

#### GitHub Handler (`utils/github_handler.py`)
- Управляет загрузкой файлов в репозиторий GitHub
- Обрабатывает конфликты SHA и повторные попытки обновления
- Обновляет информацию о файлах
- Использует GitHub API через библиотеку PyGithub
- Реализует экспоненциальную задержку при конфликтах SHA
- Поддерживает параллельную загрузку файлов через ThreadPoolExecutor
- Проверяет лимиты GitHub API и выводит предупреждения
- Сравнивает содержимое файлов для избежания лишних коммитов

## Алгоритм работы (Pipeline Flow)

### 1. DOWNLOAD PHASE
```
├─ Fetch из URLS.txt (default section) → all_configs
├─ Fetch из URLS.txt (extra_bypass section) → extra_bypass_configs
├─ Fetch из URLS.txt (yaml section) → конвертация YAML → VPN URLs
├─ Fetch из daily-updated repo → daily_configs
├─ Load manual servers → manual_configs
└─ Scan контента на Telegram прокси → mtproto_proxies, socks5_proxies
```

### 2. DEFAULT FILES GENERATION
```
├─ create_numbered_default_files() → 1.txt, 2.txt, ... (по источникам)
├─ create_all_configs_file() → all.txt (дедуплицированные)
└─ create_secure_configs_file() → all-secure.txt (security-filtered)
```

### 3. BYPASS FILES GENERATION
```
├─ apply_sni_cidr_filter() к основным конфигам → sni_cidr_filtered
├─ Add extra bypass configs (без SNI/CIDR фильтрации)
├─ Deduplicate
├─ Security filter → bypass-all-raw.txt (в /raw/)
├─ Create unsecure version → bypass-unsecure-all-raw.txt (в /raw/)
├─ _verify_config_file() → верификация через Xray-core
└─ Сортировка по пингу → bypass-all.txt, bypass-unsecure-all.txt
```

### 4. PROTOCOL SPLITTING
```
├─ Классификация по протоколу (vless, vmess, trojan, ss, ssr, tuic, hysteria, hy2)
├─ Создание secure вариантов (filter insecure)
└─ Создание unsecure вариантов (все конфиги)
```

### 5. TELEGRAM PROXY PROCESSING
```
├─ Merge scraped + manual proxies
├─ Верификация через telegram_proxy_verifier
├─ Сортировка по латентности
└─ Создание all.txt, MTProto.txt, socks.txt
```

### 6. UPLOAD PHASE
```
├─ Upload via GitHub API (local mode с токеном)
└─ Или git команды (GitHub Actions mode с --use-git)
```

## Система верификации

### Двухуровневая архитектура

1. **Raw файлы** (`/raw/` подпапки):
   - Создаются сразу после загрузки и фильтрации
   - Не проходят тестирование
   - Используются как входные данные для верификации

2. **Verified файлы** (основные папки):
   - Проходят тестирование через Xray-core
   - Сортируются по пингу (fastest first)
   - Готовы к использованию в продакшене

### Xray Batch Testing

**Архитектура (v2rayN-стиль):**
- **Один процесс Xray** на батч (100 конфигов)
- **Множество inbound/outbound** в одном конфиге
- **Динамическое выделение портов** (BASE_PORT = 20000, диапазон 5000)
- **Параллельное тестирование** через разные порты

**Платформенные различия:**
```python
# Linux/WSL
if sys.platform == "linux":
    return self._test_batch_async_wrapper()  # Async + curl_cffi

# Windows
else:
    return self._test_batch_single()  # ThreadPoolExecutor + sync
```

**Пайплайн тестирования одного конфига:**
1. Валидация URL (`_quick_validate_url()`)
2. Генерация Xray конфига (`create_single_outbound_config()`)
3. Старт Xray процесса (`start_xray_instance()`)
4. HTTP тест через SOCKS прокси (`test_through_socks()`)
5. Cleanup процесса (`stop_xray_process()`)

**Fallback механизмы:**
- TCP пинг при неудаче Xray
- TLS handshake для TLS/Reality конфигов
- Retry логика с экспоненциальной задержкой

### Оптимизации производительности

#### Параллелизм
- **ThreadPoolExecutor** для загрузок (16 workers по умолчанию)
- **Параллельная запись файлов** через ThreadPoolExecutor
- **Конкурентное тестирование** (до 300 одновременных на Linux, 150 на Windows)

#### Кэширование
- **DNS кэш** с TTL 60 секунд (lock-free)
- **Хост/порт экстракция** кэш для избежания повторных парсингов
- **Connection pooling** в curl_cffi сессиях

#### Сетевые оптимизации
- **curl_cffi** вместо requests (2-3x быстрее, TLS fingerprinting)
- **SOCKS прокси формат** `socks://` для curl_cffi совместимости
- **HTTP сессии** с retry адаптерами

#### Управление ресурсами
- **Батч-тестирование** (100 конфигов на Xray процесс)
- **Динамическое выделение портов** с авто-сбросом
- **Process cleanup** с signal handlers и atexit hooks
- **Агрессивный spam filtering** для логов Xray

## Безопасность

### Детекция insecure конфигов

Функция `has_insecure_setting()` проверяет:

**VMess:**
- `insecure`, `allowInsecure` = true/1/'true'/'1'
- `security`/`scy` = 'none'
- `alterId`/`aid` > 0 (MD5 authentication vulnerability)

**VLESS:**
- `allowInsecure`, `insecure` в URL параметрах
- `security=none`
- `encryption=none` (если нет TLS/REALITY)

**Trojan:**
- `allowInsecure`, `insecure` параметры

**Shadowsocks:**
- Слабые шифры: `rc4-md5`, `aes-*-cfb`, `bf-cfb`, `salsa20`, `chacha20`
- Белый список безопасных методов

**ShadowsocksR:**
- Парсинг SSR формата: `ssr://base64(host:port:protocol:method:obfs:base64(password))`
- Проверка метода шифрования

**TUIC:**
- `skip-cert-verify` параметр

**Общие:**
- `verify=0`, `verify=false`
- `insecure=1/true/yes/on`

### SNI/CIDR фильтрация

**Назначение:** Обход мобильных белых списков (Россия и др.)

**Процесс:**
1. Загрузка доменов из `whitelist-all.txt` (Avito, Yandex, Mail.ru, etc.)
2. Загрузка CIDR из `cidrwhitelist.txt`
3. Извлечение host/port из конфига
4. Проверка на совпадение с whitelist
5. Фильтрация несовпадающих

**Результат:**
- `bypass/` - secure конфиги (security + SNI/CIDR filtered)
- `bypass-unsecure/` - все конфиги (только SNI/CIDR filtered)

## Оптимизации

### Параллельные загрузки
- **ThreadPoolExecutor** с 16 workers для одновременной загрузки из多个 источников
- **Параллельная запись файлов** через ThreadPoolExecutor для split файлов
- **Конкурентное тестирование** с платформенными лимитами (300 Linux, 150 Windows)

### Кэширование и проверка изменений
- **DNS кэш** с TTL 60 секунд (lock-free, shared aiodns resolver)
- **Сравнение содержимого** перед загрузкой для избежания лишних коммитов
- **Хост/порт экстракция кэш** для избежания повторных парсингов

### Управление файлами
- **Разделение больших файлов**: макс. 300 конфигов на файл или 49MB (лимит GitHub)
- **Динамическое выделение портов**: BASE_PORT=20000, диапазон 5000, авто-сброс
- **Process cleanup**: signal handlers (SIGINT, SIGTERM) + atexit hooks

### Сетевые оптимизации
- **curl_cffi integration**: 2-3x быстрее requests + TLS fingerprinting + обход анти-ботов
- **SOCKS прокси формат**: `socks://` для curl_cffi (не `socks5://`)
- **Connection pooling**: curl_cffi сессии с retry адаптерами
- **Smart batching**: группировка конфигов по хосту для DNS cache эффективности

### v2rayN-стиль архитектура
- **Один Xray процесс** на батч (100 конфигов) вместо 100 процессов
- **Множество inbound/outbound** в одном конфиге
- **1000x reduction** в process overhead
- **Пайплайн тестирование**: Xray startup перекрывается с HTTP тестами

### Error handling
- **Агрессивный spam filtering** для логов Xray (фильтрует banner, goroutine traces)
- **Error categorization** с трекингом статистики
- **Retry логика** с экспоненциальной задержкой для GitHub API
- **Fallback механизмы**: TCP + TLS handshake когда Xray fails

### Потокобезопасность
- **Lock-free DNS кэш** для высокой конкуренции
- **Thread-local sessions** для избежания contention
- **Results locks** для агрегации результатов тестирования
- **Port allocation locks** для атомарного выделения портов