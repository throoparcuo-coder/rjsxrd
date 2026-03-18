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
- `xray_tester.py` - Xray-core тестирование с сортировкой по скорости
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

#### XrayTester (`utils/xray_tester.py`)
**Xray-core тестирование с сортировкой по скорости:**

- **Один процесс Xray на конфиг** для максимальной совместимости
- **Конкурентное тестирование** через разные порты
- **Динамическое выделение портов** (диапазоны: 20000-21999 batch, 22000-23999 chains, 24000-24999 persistent)
- **Платформенная оптимизация**:
  - Linux/WSL: async + curl_cffi AsyncSession (до 300 concurrent)
  - Windows: ThreadPoolExecutor + sync requests (до 150 concurrent)
- **Пайплайн тестирование**:
  1. Валидация URL
  2. Генерация Xray конфига
  3. Старт Xray процесса
  4. HTTP тест через SOCKS прокси (curl_cffi с remote DNS)
  5. Cleanup процесса
- **Сортировка результатов** по пингу (fastest first)
- **Кэширование ошибок** для дебаггинга

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

### Xray Testing

**Архитектура:**
- **Один процесс Xray на конфиг** для максимальной совместимости
- **Конкурентное тестирование** через разные порты
- **Динамическое выделение портов** (BASE_PORT = 20000, диапазоны: 20000-21999 batch, 22000-23999 chains, 24000-24999 persistent)
- **Параллельное тестирование** через ThreadPoolExecutor/async

**Платформенные различия:**
```python
# Linux/WSL
if sys.platform != "win32":
    return self._test_batch_async_wrapper()  # Async + curl_cffi (до 300 concurrent)

# Windows
else:
    return self._test_batch_single()  # ThreadPoolExecutor + sync (до 150 concurrent)
```

**Пайплайн тестирования одного конфига:**
1. Валидация URL (`_quick_validate_url()`)
2. Генерация Xray конфига (`create_single_outbound_config()`)
3. Старт Xray процесса (`start_xray_instance()`)
4. HTTP тест через SOCKS прокси с remote DNS (`test_through_socks()` → `socks5h://`)
5. Cleanup процесса (`stop_xray_process()`)

**Retry логика:**
- Максимум 2 попытки на конфиг
- Экспоненциальная задержка между попытками

### Оптимизации производительности

#### Параллелизм
- **ThreadPoolExecutor** для загрузок (16 workers по умолчанию)
- **Параллельная запись файлов** через ThreadPoolExecutor
- **Конкурентное тестирование** (до 300 одновременных на Linux, 150 на Windows)

#### Кэширование
- **DNS кэш** с TTL 60 секунд (lock-free, aiodns resolver)
- **Хост/порт экстракция** кэш для избежания повторных парсингов
- **Connection pooling** в curl_cffi сессиях

#### Сетевые оптимизации
- **curl_cffi** вместо requests (2-3x быстрее, TLS fingerprinting, обход анти-ботов)
- **SOCKS прокси формат** `socks://` для curl_cffi совместимости
- **HTTP сессии** с retry адаптерами
- **Remote DNS** через `socks5h://` для предотвращения DNS leaks

#### Управление ресурсами
- **Конкурентное тестирование** (один Xray процесс на конфиг)
- **Динамическое выделение портов** с проверкой доступности
- **Process cleanup** с signal handlers и atexit hooks
- **Агрессивный spam filtering** для логов Xray
- **psutil fallback** для гарантированного завершения процессов

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
- **Динамическое выделение портов**: BASE_PORT=20000, проверка доступности через socket.bind()
- **Process cleanup**: signal handlers (SIGINT, SIGTERM) + atexit hooks + psutil fallback

### Сетевые оптимизации
- **curl_cffi integration**: 2-3x быстрее requests + TLS fingerprinting + обход анти-ботов
- **SOCKS прокси формат**: `socks://` для curl_cffi (не `socks5://`)
- **Remote DNS**: `socks5h://` для предотвращения DNS leaks
- **Connection pooling**: curl_cffi сессии с retry адаптерами

### Error handling
- **Агрессивный spam filtering** для логов Xray (фильтрует banner, goroutine traces, runtime errors)
- **Error categorization** с трекингом статистики
- **Retry логика** с экспоненциальной задержкой для GitHub API
- **Secure temp files**: `tempfile.mkstemp()` с `chmod 0600` для защиты credentials

### Потокобезопасность
- **Lock-free DNS кэш** для высокой конкуренции
- **Thread-local sessions** для избежания contention
- **Results locks** для агрегации результатов тестирования
- **Port allocation locks** для атомарного выделения портов с проверкой доступности