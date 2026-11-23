# Проектирование и архитектура

ИС предназначена для оформления аренды экскаваторов и автокранов, предварительного расчёта доставки и защищённой выдачи PDF-договоров.

## Матрица доступа

| Операция | Гость | Клиент | Сотрудник | Администратор |
| --- | --- | --- | --- | --- |
| Каталог | Да | Да | Да | Да |
| Создать заявку | Нет | Да | Нет | Нет |
| Читать заявку | Нет | Своя | Все | Нет |
| Отменить new | Нет | Своя | Все | Нет |
| Подтвердить и закрыть | Нет | Нет | Да | Нет |
| Загрузить PDF | Нет | Нет | Да | Нет |
| Скачать PDF | Нет | Своя | Все | Нет |
| Читать аудит | Нет | Нет | Нет | Да |

Роль при регистрации всегда client. Привилегированные аккаунты создаются CLI-командой create-user. При чтении объекта сервер проверяет роль и владельца.

## Архитектура

```mermaid
flowchart LR
    B[Браузер и HTML формы] --> F[Flask и Jinja]
    F --> A[Проверка сессии и роли]
    F --> O[SQLAlchemy и psycopg2]
    F --> C[AES GCM]
    C --> O
    O --> P[(PostgreSQL)]
    E[Ключ из окружения] --> C
    P --> V[Агрегаты заявок]
    V --> D[CSV и Yandex DataLens]
```

## ER диаграмма

```mermaid
erDiagram
    USER ||--o{ LOGIN_SESSION : has
    USER ||--o{ RENTAL : creates
    USER o|--o{ AUDIT : actor
    MACHINE ||--o{ RENTAL : selected
    RENTAL ||--o| CONTRACT : has
    USER {
        uuid id PK
        varchar login UK
        text password_hash
        bytea phone
        varchar role
    }
    LOGIN_SESSION {
        varchar id PK
        uuid user_id FK
        timestamptz expires
    }
    MACHINE {
        integer id PK
        varchar name
        varchar kind
        integer hourly
        integer dispatch
        integer per_km
    }
    RENTAL {
        uuid id PK
        uuid user_id FK
        integer machine_id FK
        date day
        integer hours
        numeric km
        numeric delivery
        numeric total
        varchar status
        varchar note
    }
    CONTRACT {
        uuid id PK
        uuid rental_id FK,UK
        bytea blob
        integer key_version
    }
    AUDIT {
        integer id PK
        timestamptz at
        uuid actor FK
        varchar action
        uuid target
    }
```

Модели находятся в [app.py](../app.py). Схема ORM создаётся командой init-db. rental_id договора уникален. Цена сохраняется в NUMERIC(12,2), расстояние в NUMERIC(8,2). Классы User и LoginSession создают таблицы user и login_session.

## Конфиденциальные поля и инструменты

| Данные | Хранение | Инструмент |
| --- | --- | --- |
| Пароль | Хеш Argon2id с солью и параметрами | argon2-cffi |
| Телефон | AES-256-GCM, контекст связан с UUID пользователя | cryptography |
| PDF договора | BYTEA, nonce и шифротекст с тегом, AAD содержит UUID заявки и договора | cryptography |
| Сессия | Случайный SID, серверная таблица, срок два часа | Flask session и LoginSession |
| SQL | Параметризованные выражения ORM | Flask-SQLAlchemy |
| POST формы | CSRF-токены | Flask-WTF |

Пароль проверяется через verify. Восстановление телефона и договора требует отдельного ключа DATA_KEY.

