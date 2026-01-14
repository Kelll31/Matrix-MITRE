# Просмотрщик матрицы MITRE ATT&CK

Полнофункциональное веб-приложение для просмотра, управления и анализа матрицы MITRE ATT&CK с автоматическим обновлением, интеллектуальным кэшированием и интерактивным пользовательским интерфейсом.

## Описание

Это приложение предоставляет полную реализацию просмотрщика матрицы MITRE ATT&CK с высокопроизводительным бэкендом на FastAPI и современным отзывчивым фронтенднотом. Приложение автоматически загружает и кэширует последние данные MITRE ATT&CK из официального репозитория GitHub, обеспечивая быстрый поиск и комплексный анализ техник и тактик атак.

## Основные возможности

- **FastAPI бэкенд** - Асинхронный, production-ready API с полной типизацией
- **Интерактивный фронтенд** - Современный отзывчивый интерфейс с тёмной темой и плавными анимациями
- **Автоматическое обновление** - Настраиваемые интервалы обновления от 1 часа до 7 дней
- **Умное кэширование** - Локальное JSON кэширование для мгновенного доступа к данным
- **Продвинутый поиск** - Полнотекстовый поиск по названиям, ID, описаниям и платформам
- **Панель статистики** - Точная информация о тактиках, техниках и подтехниках в реальном времени
- **Кроссплатформенность** - Безупречная работа на десктопе, планшете и мобильных устройствах
- **Русский язык** - Полная поддержка кириллицы и локализации
- **Production-ready** - Оптимизировано для развертывания на боевые серверы

## Технологический стек

### Бэкенд
- Python 3.9 и выше
- FastAPI 0.104+ - Современный асинхронный веб-фреймворк с встроенной документацией API
- Uvicorn - ASGI приложение сервер
- aiohttp - Асинхронный HTTP клиент для параллельных запросов
- Pydantic - Валидация данных с использованием type annotations
- python-dotenv - Управление конфигурацией через переменные окружения

### Фронтенд
- HTML5 и CSS3 - Семантическая вёрстка и современные стили
- Vanilla JavaScript (ES6+) - Чистый JavaScript без зависимостей от фреймворков
- Axios - Promise-based HTTP клиент
- Bootstrap 5 CDN - Отзывчивый CSS фреймворк
- Font Awesome 6 - Богатая иконография

### Источник данных
- MITRE ATT&CK Enterprise Framework - Официальный репозиторий с STIX JSON форматом

## Установка и запуск

### Необходимые компоненты

Захеръте, что на вашей системе установлены Python 3.9+ и pip.

### Шаг 1: Клонирование репозитория

```bash
git clone https://github.com/Kelll31/Matrix-MITRE.git
cd Matrix-MITRE
```

### Шаг 2: Создание виртуального окружения

Для Windows:
```bash
python -m venv venv
venv\Scripts\activate
```

Для Linux/macOS:
```bash
python3 -m venv venv
source venv/bin/activate
```

### Шаг 3: Установка зависимостей

```bash
pip install -r requirements.txt
```

### Шаг 4: Запуск приложения

```bash
python main.py
```

Приложение будет доступно по адресу: **http://localhost:8000**

## Спецификация парсинга MITRE данных

### Источник данных

Приложение загружает данные из официального GitHub репозитория MITRE ATT&CK:
```
https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
```

Данные поступают в формате STIX (Structured Threat Information Expression) JSON, который содержит структурированную информацию об атак.

### Структура исходного STIX JSON

Оригинальный файл содержит объекты следующих типов:

#### 1. Объекты типа `x-mitre-tactic`

Представляют 14 основных тактик MITRE ATT&CK матрицы.

**Извлекаемые поля:**
- `name` - Полное название тактики (например: "Persistence", "Initial Access")
- `description` - Подробное описание тактики и её назначения
- `x_mitre_shortname` - Сокращённое имя тактики для использования в URL (например: "persistence", "initial-access")

**Пример исходного объекта:**
```json
{
  "type": "x-mitre-tactic",
  "id": "x-mitre-tactic--...",
  "created": "2018-04-05T20:45:48.005Z",
  "modified": "2020-01-10T16:41:33.561Z",
  "name": "Persistence",
  "description": "The adversary has taken steps to ensure they can maintain their foothold...",
  "x_mitre_shortname": "persistence"
}
```

#### 2. Объекты типа `attack-pattern`

Представляют техники и подтехники атак (разделены флагом `x_mitre_is_subtechnique`).

**Извлекаемые поля для техник (x_mitre_is_subtechnique = false):**

| Поле | Тип | Описание | Пример |
|------|-----|---------|--------|
| `name` | string | Название техники | "Data Obfuscation" |
| `description` | string | Подробное описание техники | "Adversaries may obfuscate data..." |
| `x_mitre_platforms` | array | Поддерживаемые ОС платформы | ["Windows", "Linux", "macOS"] |
| `kill_chain_phases` | array | Связанные фазы атаки | [{"phase_name": "command-and-control"}] |
| `external_references` | array | Внешние источники и ID | Смотри раздел ниже |
| `x_mitre_detection` | string | Методы обнаружения техники | "Monitor for unusual network connections..." |
| `x_mitre_is_subtechnique` | boolean | Флаг подтехники | false |

**Извлекаемые поля для подтехник (x_mitre_is_subtechnique = true):**

Те же поля, что и для техник, плюс:
- Содержат тот же `kill_chain_phases` для связи с родительской техникой
- ID в формате `T1234.001` (родительская техника + номер подтехники)

**Пример исходного объекта техники:**
```json
{
  "type": "attack-pattern",
  "id": "attack-pattern--01a5a209-b94c-450b-b7f9-946ce02218cb",
  "created": "2016-02-19T23:46:38.422Z",
  "modified": "2024-01-10T15:40:22.130Z",
  "name": "Data Obfuscation",
  "description": "Adversaries may obfuscate command and control traffic...",
  "kill_chain_phases": [
    {
      "kill_chain_name": "mitre-attack",
      "phase_name": "command-and-control"
    }
  ],
  "x_mitre_detection": "Monitor for data obfuscation traffic patterns...",
  "x_mitre_is_subtechnique": false,
  "x_mitre_platforms": ["Windows", "Linux", "macOS"],
  "external_references": [
    {
      "source_name": "mitre-attack",
      "url": "https://attack.mitre.org/techniques/T1001/",
      "external_id": "T1001"
    },
    {
      "source_name": "Wikipedia",
      "url": "https://en.wikipedia.org/wiki/Data_obfuscation"
    }
  ]
}
```

**Пример исходного объекта подтехники:**
```json
{
  "type": "attack-pattern",
  "id": "attack-pattern--...",
  "created": "2019-04-25T20:54:15.265Z",
  "modified": "2024-01-10T15:40:22.130Z",
  "name": "Junk Data",
  "description": "Adversaries may add junk data to network packets...",
  "kill_chain_phases": [
    {
      "kill_chain_name": "mitre-attack",
      "phase_name": "command-and-control"
    }
  ],
  "x_mitre_detection": "Monitor for unusual network packet patterns...",
  "x_mitre_is_subtechnique": true,
  "x_mitre_platforms": ["Windows", "Linux", "macOS"],
  "external_references": [
    {
      "source_name": "mitre-attack",
      "url": "https://attack.mitre.org/techniques/T1001/001/",
      "external_id": "T1001.001"
    }
  ]
}
```

### Процесс парсинга в приложении

#### Шаг 1: Загрузка и валидация JSON

```python
# Загрузка с GitHub
async with aiohttp.ClientSession() as session:
    async with session.get(GITHUB_URL) as response:
        text = await response.text()
        data = json.loads(text)  # Парсинг JSON
```

#### Шаг 2: Первый проход - Сбор тактик

Приложение итерирует через все объекты и находит все тактики:

```python
for obj in objects:
    if obj.get("type") == "x-mitre-tactic":
        tactic_name = obj.get("name").lower().replace(" ", "-")
        tactics[tactic_name] = {
            "name": obj.get("name"),           # "Persistence"
            "description": obj.get("description"),
            "shortname": obj.get("x_mitre_shortname")  # "persistence"
        }
        matrix[tactic_name] = []  # Инициализация массива техник
```

#### Шаг 3: Второй проход - Сбор техник и подтехник

Приложение собирает техники и подтехники с расширенной информацией:

```python
for obj in objects:
    if obj.get("type") == "attack-pattern":
        is_subtechnique = obj.get("x_mitre_is_subtechnique", False)
        
        # Извлечение kill chain phases (тактики)
        kill_chain = obj.get("kill_chain_phases", [])
        tactic_names = [kc.get("phase_name", "").lower() 
                       for kc in kill_chain]
        
        # Извлечение ATT&CK ID из external_references
        external_refs = obj.get("external_references", [])
        external_id = "N/A"
        mitre_url = None
        
        for ref in external_refs:
            source_name = ref.get("source_name", "").lower()
            if source_name in {"mitre-attack", "attack", "mitre"}:
                external_id = ref.get("external_id", external_id)
                mitre_url = ref.get("url", mitre_url)
                break
        
        # Формирование объекта техники
        tech_data = {
            "id": external_id,                           # T1001 или T1001.001
            "name": obj.get("name", "Unknown"),         # "Data Obfuscation"
            "description": obj.get("description", ""),  # Полное описание
            "platforms": obj.get("x_mitre_platforms", []),  # ["Windows", ...]
            "tactics": tactic_names,                    # ["command-and-control"]
            "mitre_url": mitre_url,                     # https://attack.mitre.org/...
            "detection": obj.get("x_mitre_detection", "Нет данных"),  # Методы
            "external_references": formatted_refs,  # Массив ссылок
            "kill_chain_phases": [kc.get("phase_name") for kc in kill_chain],
            "stix_id": obj.get("id", "")  # Оригинальный STIX ID
        }
        
        # Разделение техник и подтехник
        if is_subtechnique:
            subtechniques[obj.get("id")] = tech_data
        else:
            techniques[obj.get("id")] = tech_data
```

#### Шаг 4: Построение иерархии подтехник

Приложение связывает подтехники с их родительскими техниками по ID:

```python
# Для каждой техники находим связанные подтехники
for tech_obj_id, technique in techniques.items():
    technique_subtechniques = []
    
    for sub_obj_id, subtech in subtechniques.items():
        # Сравнение ID: если подтехника начинается с ID техники
        # T1001.001 начинается с T1001.
        if subtech["id"].startswith(technique["id"] + "."):
            technique_subtechniques.append(subtech)
    
    # Добавление подтехник в объект техники
    technique["subtechniques"] = sorted(
        technique_subtechniques, 
        key=lambda x: x["id"]
    )
```

#### Шаг 5: Создание индексов поиска

Для быстрого поиска создаются хэш-индексы по ID техник и подтехник:

```python
# Индекс техник по ID для O(1) поиска
for tech_id, tech_data in techniques.items():
    technique_index[tech_data["id"].upper()] = tech_data

# Индекс подтехник по ID для O(1) поиска
for sub_id, sub_data in subtechniques.items():
    subtechnique_index[sub_data["id"].upper()] = sub_data
```

#### Шаг 6: Построение матрицы

Техники группируются по тактикам:

```python
for tactic in technique["tactics"]:
    if tactic in matrix:
        matrix[tactic].append(technique_obj)

# Сортировка техник по ID внутри каждой тактики
for tactic_key in matrix:
    matrix[tactic_key].sort(key=lambda x: x["id"])
```

### Структура финального объекта

После парсинга приложение создает структурированный объект:

```json
{
  "tactics": {
    "persistence": {
      "name": "Persistence",
      "shortname": "persistence",
      "description": "..."
    },
    "initial-access": {
      "name": "Initial Access",
      "shortname": "initial-access",
      "description": "..."
    }
  },
  "matrix": {
    "persistence": [
      {
        "id": "T1098",
        "name": "Account Manipulation",
        "description": "...",
        "platforms": ["Windows", "Linux", "macOS"],
        "tactics": ["persistence"],
        "mitre_url": "https://attack.mitre.org/techniques/T1098/",
        "detection": "...",
        "external_references": [...],
        "kill_chain_phases": ["persistence"],
        "subtechniques": [
          {
            "id": "T1098.001",
            "name": "Additional Cloud Credentials",
            "description": "...",
            "platforms": ["AWS", "GCP", "Azure"],
            "tactics": ["persistence"],
            "mitre_url": "https://attack.mitre.org/techniques/T1098/001/",
            "detection": "...",
            "external_references": [...],
            "kill_chain_phases": ["persistence"]
          },
          {
            "id": "T1098.002",
            "name": "Exchange Email Delegate Permissions",
            "description": "...",
            "platforms": ["Windows"],
            "tactics": ["persistence"],
            "mitre_url": "https://attack.mitre.org/techniques/T1098/002/",
            "detection": "...",
            "external_references": [...],
            "kill_chain_phases": ["persistence"]
          }
        ]
      }
    ]
  },
  "technique_index": {
    "T1001": {...},
    "T1002": {...},
    "T1098": {...}
  },
  "subtechnique_index": {
    "T1001.001": {...},
    "T1098.001": {...},
    "T1098.002": {...}
  },
  "statistics": {
    "total_tactics": 14,
    "total_techniques": 234,
    "total_subtechniques": 543
  }
}
```

### Таблица преобразования полей

| Исходное поле STIX | Поле приложения | Тип | Обработка |
|-------------------|-----------------|-----|----------|
| `type` | - | - | Фильтр для определения объекта |
| `name` | `name` | string | Прямое копирование |
| `description` | `description` | string | Копирование или "Описание недоступно" |
| `x_mitre_shortname` | `shortname` | string | Используется для URL тактики |
| `kill_chain_phases[].phase_name` | `tactics`, `kill_chain_phases` | array | Преобразование в нижний регистр |
| `x_mitre_platforms` | `platforms` | array | Прямое копирование |
| `x_mitre_detection` | `detection` | string | Копирование или "Нет данных о детекции" |
| `x_mitre_is_subtechnique` | - | boolean | Флаг для разделения техник |
| `external_references[].source_name` | - | - | Фильтр для поиска MITRE ID |
| `external_references[].external_id` | `id` | string | Извлечение ATT&CK ID (T1234 или T1234.001) |
| `external_references[].url` | `mitre_url` | string | Извлечение URL на official MITRE сайт |
| `external_references[]` | `external_references` | array | Полное копирование для доступа к источникам |
| `id` | `stix_id` | string | Оригинальный STIX ID (в целях отладки) |

### Особенности парсинга

1. **Безопасная обработка JSON**: Все операции парсинга обёрнуты в try-except для корректной обработки некорректных данных

2. **Нормализация ID**: Все ID техник приводятся к верхнему регистру для унифицированного поиска

3. **Иерархия подтехник**: Подтехники автоматически связываются с родительскими техниками по префиксу ID (T1234.001 связана с T1234)

4. **Многоязычная поддержка**: Описания и тактики сохраняются в UTF-8 для полной поддержки локализации

5. **Фильтрация**: Техники без корректного ATT&CK ID пропускаются (если ID не начинается с "T")

6. **Индексирование**: Два независимых индекса для O(1) поиска техник и подтехник

7. **Сортировка**: Техники внутри тактик и подтехники внутри техник сортируются по ID

### Типичные размеры данных

- **Всего тактик**: 14
- **Всего техник**: ~234
- **Всего подтехник**: ~543
- **Размер кэша**: ~2-3 МБ
- **Время парсинга**: ~1-2 секунды

## Справка по API

### Endpoints для получения данных

#### Полная матрица
```
GET /api/matrix
```
Возвращает полную матрицу MITRE ATT&CK со всеми тактиками, техниками и подтехниками.

#### Статистика
```
GET /api/statistics
```

Ответ:
```json
{
  "total_tactics": 14,
  "total_techniques": 234,
  "total_subtechniques": 543,
  "last_update": "2026-01-14T12:34:56",
  "update_interval": "24_hours",
  "is_updating": false,
  "update_count": 5
}
```

#### Все тактики
```
GET /api/matrix/tactics
```
Возвращает список всех доступных тактик с описаниями и сокращениями.

#### Детали тактики
```
GET /api/matrix/tactic/{имя_тактики}
```

Пример: `GET /api/matrix/tactic/persistence`

Возвращает все техники, связанные с указанной тактикой.

#### Техника по ID
```
GET /api/matrix/technique/{техника_id}
```

Примеры:
- `GET /api/matrix/technique/T1001`
- `GET /api/matrix/technique/T1001.001`

Возвращает полную информацию о технике или подтехнике, включая описание, поддерживаемые платформы, методы детекции и внешние ссылки.

#### Техники тактики с фильтрацией
```
GET /api/matrix/tactics/{тактика}/techniques
```

Параметры запроса:
- `platform` (опционально) - Фильтр по платформе (Windows, Linux, macOS и т.д.)
- `limit` (опционально) - Максимальное количество результатов

Пример: `GET /api/matrix/tactics/persistence/techniques?platform=Windows&limit=10`

#### Поиск техник
```
GET /api/search?q={запрос}&limit={лимит}
```

Параметры:
- `q` - Строка поиска (обязательно, минимум 1 символ)
- `limit` - Максимум результатов (по умолчанию: 20, максимум: 100)

Поиск осуществляется по:
- Названиям техник
- ID техник
- Описаниям
- Поддерживаемым платформам

Примеры:
- `GET /api/search?q=T1001` - Поиск по ID
- `GET /api/search?q=Process` - Поиск по описанию
- `GET /api/search?q=Windows&limit=50` - Поиск по платформе с пользовательским лимитом

### Endpoints управления и конфигурации

#### Изменение интервала обновления
```
POST /api/settings/update-interval
Content-Type: application/json

{
  "interval": "24_hours"
}
```

Доступные интервалы:
- `1_hour` - Обновление каждый час
- `6_hours` - Обновление каждые 6 часов
- `12_hours` - Обновление каждые 12 часов
- `24_hours` - Обновление каждый день (по умолчанию)
- `7_days` - Обновление каждую неделю

#### Немедленное обновление
```
POST /api/matrix/refresh
```

Запускает немедленную загрузку и парсинг последней матрицы MITRE ATT&CK с GitHub. Возвращает подтверждение обновления с временной меткой.

## Интервалы обновления

Приложение поддерживает гибкий график автоматических обновлений для баланса между актуальностью данных и потреблением ресурсов:

| Интервал | Длительность | Применение |
|----------|--------------|----------|
| 1_hour | 3600 секунд | Высокочастотный анализ угроз |
| 6_hours | 21600 секунд | Мониторинг в рабочие часы |
| 12_hours | 43200 секунд | Сбалансированный подход |
| 24_hours | 86400 секунд | Ежедневная синхронизация (рекомендуется) |
| 7_days | 604800 секунд | Низконагруженные окружения |

## Пользовательский интерфейс

### Панель управления
- Статистика в реальном времени с количеством тактик, техник и подтехник
- Временная метка последнего обновления с счётчиком обновлений
- Кнопка ручного обновления для немедленного контакта с GitHub
- Выпадающий список для настройки интервала автоматических обновлений

### Матрица тактик
- Полный обзор всех 14 тактик MITRE ATT&CK
- Интерактивные карточки с информацией о каждой тактике
- Количество техник для каждой тактики
- Эффекты наведения и плавные переходы
- Прямая навигация к деталям техник

### Просмотрщик техник
- Комплексный список всех техник выбранной тактики
- ID, название и поддерживаемые платформы для быстрой ориентации
- Расширяемые детали с полными описаниями
- Методы детекции и стратегии смягчения последствий
- Ссылки на официальные страницы MITRE ATT&CK
- Иерархия подтехник и взаимосвязи

### Интерфейс поиска
- Результаты поиска в реальном времени с несколькими критериями сопоставления
- Фильтрация результатов по тактике
- Быстрая навигация к полным деталям техники
- Поддержка пагинации для больших наборов результатов

## Структура проекта

```
Matrix-MITRE/
├── main.py                    # FastAPI приложение со всеми endpoints
├── requirements.txt           # Зависимости Python
├── README.md                  # Документация проекта
├── .gitignore                 # Конфигурация Git ignore
├── cache/                     # Директория локального кэша (создаётся автоматически)
│   ├── mitre_matrix.json      # Кэшированная матрица MITRE ATT&CK
│   └── metadata.json          # Метаданные и временные метки кэша
└── frontend/                  # Веб-интерфейс
    └── index.html             # Полный HTML/CSS/JS интерфейс
```

## Процесс обновления матрицы

### Инициализация приложения
1. Приложение проверяет наличие локального кэша
2. Если кэш существует и действителен, данные загружаются немедленно
3. Если кэш отсутствует или устарел, загрузка происходит с GitHub
4. Запускается фоновая задача для периодических обновлений

### Цикл фонового обновления
1. Ожидание настроенного интервала обновления
2. Загрузка последних данных MITRE ATT&CK в формате STIX JSON
3. Парсинг и валидация структуры данных
4. Построение индексов поиска для быстрых поисков
5. Обновление локальных файлов кэша
6. Логирование завершения обновления с временной меткой
7. Увеличение счётчика обновлений

### Технические детали реализации
- Все сетевые запросы полностью асинхронные (неблокирующие)
- Парсинг JSON включает комплексную обработку ошибок
- Кэширование использует кодирование UTF-8 для полной поддержки кириллицы
- CORS (Cross-Origin Resource Sharing) включен для сценариев интеграции
- Эффективная индексация обеспечивает поиск техник за микросекунды

## Модель данных

Приложение парсит MITRE STIX JSON данные в следующую структуру:

### Объект техники
```json
{
  "id": "T1001",
  "name": "Обфускация данных",
  "description": "Обфускация данных...",
  "platforms": ["Windows", "Linux", "macOS"],
  "tactics": ["command-and-control"],
  "mitre_url": "https://attack.mitre.org/techniques/T1001/",
  "detection": "Метод детекции...",
  "external_references": [...],
  "kill_chain_phases": ["command-and-control"],
  "subtechniques": [...]
}
```

### Объект тактики
```json
{
  "name": "Сохранение доступа",
  "shortname": "persistence",
  "description": "Противник стремится...",
  "techniques": [...]
}
```

## Характеристики производительности

- **Начальная загрузка**: Мгновенная при наличии кэша, 2-5 секунд при первом запуске
- **Поиск техники**: Микросекундный поиск через hash-based индексы
- **Производительность поиска**: Линейный O(n), обычно <100мс для 500 результатов
- **Размер кэша**: Приблизительно 2-3 МБ для полной матрицы
- **Использование памяти**: 50-80 МБ во время выполнения
- **Одновременные запросы**: Поддерживает 100+ одновременных пользователей

## Соображения безопасности

- CORS настроен на принятие запросов со всех источников (измените для production)
- Все входные данные валидируются через Pydantic модели
- Обработка исключений предотвращает утечку информации
- Не хранятся конфиденциальные учетные данные в коде
- Переменные окружения могут использоваться для конфигурации
- В production окружениях используйте HTTPS
- Рассмотрите внедрение rate limiting для production развертывания

## Развертывание

### Локальная разработка
```bash
python main.py
```

### Production с Gunicorn
```bash
pip install gunicorn
gunicorn main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

### Развертывание Docker

Создайте Dockerfile:
```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

Сбор и запуск:
```bash
docker build -t mitre-matrix .
docker run -p 8000:8000 -d mitre-matrix
```

### Сервис Systemd

Создайте `/etc/systemd/system/mitre-matrix.service`:
```ini
[Unit]
Description=MITRE ATT&CK Matrix Service
After=network.target

[Service]
User=www-data
WorkingDirectory=/opt/mitre-matrix
ExecStart=/usr/bin/gunicorn main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Включение и запуск:
```bash
sudo systemctl daemon-reload
sudo systemctl enable mitre-matrix
sudo systemctl start mitre-matrix
```

## Логирование

Приложение выводит подробные логи для мониторинга и отладки:

```
INFO: Application startup complete
INFO: Cache loaded from disk (JSON file)
INFO: MITRE ATT&CK matrix loaded successfully
INFO: Background update task started
INFO: Forcing immediate matrix refresh
INFO: Matrix update completed (update #5)
```

## Обработка ошибок

Приложение включает комплексную обработку ошибок:
- 503 Service Unavailable - Матрица еще не загружена
- 404 Not Found - Запрошенная техника или тактика не найдена
- 429 Too Many Requests - Обновление уже выполняется
- 400 Bad Request - Неверный параметр интервала обновления

## Статистика кода

- main.py: Приблизительно 650 строк production-ready Python кода
- index.html: Приблизительно 600 строк HTML/CSS/JavaScript
- Всего: Приблизительно 1,250 строк кода
- Не требует внешних инструментов сборки или транспилеров

## Последние обновления (v1.1)

- Исправлено DeprecationWarning для deprecated синтаксиса @app.on_event
- Миграция на современный паттерн FastAPI lifespan контекст-менеджера
- Разрешены проблемы с type annotations при валидации ответов
- Улучшена загрузка JSON с GitHub (обработка text/plain content-type)
- Реализован полнофункциональный интерактивный фронтенд интерфейс
- Улучшена обработка ошибок и логирование везде

## Вклад в проект

Вклады приветствуются! Не стеснялтесь отправлять pull requests с улучшениями, исправлениями ошибок или новыми функциями.

## Лицензия

Этот проект лицензирован под лицензией MIT - см. файл LICENSE для деталей.

## Автор

**Kelll31** - Специалист по пентестированию и кибербезопасности

- GitHub: [Kelll31](https://github.com/Kelll31)
- Специализация: Операции красной команды, анализ угроз, фреймворк MITRE ATT&CK

---

**Создано с фокусом на надежность и удобство использования для специалистов по кибербезопасности**

Последнее обновление: 14 января 2026