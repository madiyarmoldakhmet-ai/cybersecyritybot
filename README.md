# 🛡️ CyberSecurityBot — Autonomous Local & Hybrid AI Pentester & Remediation Engine

<div align="center">

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111%2B-009688.svg?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![aiogram 3.x](https://img.shields.io/badge/aiogram-3.x-2CA5E0.svg?style=for-the-badge&logo=telegram)](https://aiogram.dev/)
[![Ollama](https://img.shields.io/badge/Ollama-Local%20AI-black.svg?style=for-the-badge&logo=ollama)](https://ollama.ai/)
[![Apple Silicon M4](https://img.shields.io/badge/Hardware-M4%20Optimized-silver.svg?style=for-the-badge&logo=apple)](https://apple.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

**Автономный AI DevSecOps ассистент для разработчиков и вайбкодеров.**  
*Аудит кода (SAST), фаззинг эндпоинтов (DAST), локальный анализ уязвимостей через Ollama и автоматическое создание безопасных Pull Request.*

[Ключевые фичи](#-ключевые-возможности) • [Архитектура](#-архитектура-системы) • [Быстрый старт](#-быстрый-старт) • [Telegram Бот](#-telegram-интерфейс) • [REST API](#-fastapi-эндпоинты) • [Roadmap](#-roadmap)

</div>

---

## 🌟 Зачем нужен CyberSecurityBot?

В эпоху стремительной разработки и вайбкодинга многие проекты выходят в продакшн с критическими уязвимостями (SQL-инъекции, `eval()`, утечки секретов `sk-live-...`, ошибки в CORS и заголовках). 

**CyberSecurityBot** решает эту проблему за 60 секунд:
1. **🔐 Proof of Ownership**: проверяет права владения (`push`/`admin`) перед любым аудитом.
2. **🔍 Мульти-сканирование**: запускает глубокий статический (SAST) и динамический (DAST) аудит.
3. **🧠 100% Приватный AI на Mac (Zero-Cost)**: локальная модель `qwen2.5-coder:14b` или `deepseek-r1` в Ollama анализирует первопричину бага и генерирует безопасный патч.
4. **🚀 Auto-PR**: автоматически создает изолированную ветку `security-fix/...` и открывает подробный Pull Request на GitHub.

---

## 🏛 Архитектура системы

```text
 ┌─────────────────────────────────────────────────────────────────────────┐
 │                       ENTRYPOINTS / INTERFACES                          │
 │      Telegram Bot (aiogram 3.x)   │   FastAPI Web API / Dashboard CLI   │
 └───────────────────────────────────┬─────────────────────────────────────┘
                                     │
                    [ 1. Proof of Ownership Verification ]
                                     │
           ┌─────────────────────────┴─────────────────────────┐
           ▼                                                   ▼
 ┌──────────────────────────┐                        ┌───────────────────┐
 │       SAST ENGINE        │                        │    DAST ENGINE    │
 │ • AST Security Inspector │                        │ • CSP / HSTS      │
 │ • Semgrep Security Rules │                        │ • CORS Reflection │
 │ • Bandit AST Linters     │                        │ • Insecure Cookie │
 │ • Pip-Audit (CVEs)       │                        │ • Server Leaks    │
 └─────────────┬────────────┘                        └─────────┬─────────┘
               │                                               │
               └───────────────────────┬───────────────────────┘
                                       │
                         [ Normalized Findings JSON ]
                                       │
                                       ▼
 ┌─────────────────────────────────────────────────────────────────────────┐
 │                       AI REMEDIATION ENGINE                             │
 │  • Local Ollama (qwen2.5-coder:14b / deepseek-r1 on Apple Silicon M4)   │
 │  • Hybrid Cloud Fallback (Google Gemini 2.5 Flash API)                  │
 └─────────────────────────────────────┬───────────────────────────────────┘
                                       │
                   [ Secure Patch & Explanation Generated ]
                                       │
                                       ▼
 ┌─────────────────────────────────────────────────────────────────────────┐
 │                      AUTOMATED PULL REQUEST ENGINE                      │
 │   Creates Branch -> Writes Patch -> Opens GitHub PR with CWE/CVE Body   │
 └─────────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Ключевые возможности

- 🛡️ **Proof of Ownership**: Никакого несанкционированного сканирования. Проверка прав через GitHub OAuth / PAT API и верификацию DNS TXT записей.
- 🐍 **Встроенный AST Security Engine**: Мгновенный поиск SQL-инъекций, hardcoded секретов, `eval()`, небезопасных `subprocess(shell=True)` и уязвимой десериализации без внешних зависимостей.
- 🌐 **Dynamic Web Auditor (DAST)**: Проверка отсутствующих заголовков CSP, HSTS, X-Frame-Options, Cookie flags, утечек версий ПО и wildcard CORS конфигураций.
- 💻 **Локальный AI на Apple Silicon**: Работает офлайн на чипах серии Apple M (M1–M4) через Ollama, не отправляя ваш приватный код сторонним провайдерам.
- 🤖 **Интерактивный Telegram-бот**: Удобный аудит в 2 клика прямо со смартфона с возможностью скачать отчет в Markdown.

---

## 🚀 Быстрый старт

### 1. Клонирование и установка зависимостей

```bash
git clone https://github.com/madiyarmoldakhmet-ai/cybersecyritybot.git
cd cybersecyritybot

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Настройка переменных окружения

Скопируйте пример конфига:
```bash
cp .env.example .env
```

Отредактируйте `.env`:
```env
# Telegram Bot Token (от @BotFather)
TELEGRAM_BOT_TOKEN=123456789:AA...

# Локальный AI Движок (Ollama)
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5-coder:14b

# (Опционально) Gemini Cloud Fallback
GEMINI_API_KEY=your_gemini_api_key
```

### 3. Запуск локального LLM (Ollama)

Установите и запустите [Ollama](https://ollama.ai/):
```bash
ollama run qwen2.5-coder:14b
```

### 4. Запуск сквозного тестирования пайплайна

```bash
python3 tests/test_pipeline.py
```

---

## 📱 Telegram интерфейс

Для запуска бота:
```bash
python3 bot/main.py
```

### Сценарий работы в Telegram:
1. Пользователь вводит `/start` и нажимает **«🛡️ Начать аудит»**.
2. Передает GitHub токен и ссылку на репозиторий: `madiyarmoldakhmet-ai/cybersecyritybot`.
3. Бот проверяет права владения -> запускает SAST сканирование -> выдает интерактивную сводку.
4. По кнопке **«🤖 Сгенерировать AI-исправление и PR»** бот создает Pull Request на GitHub с безопасным кодом!

---

## 🌐 FastAPI эндпоинты

Запуск веб-сервера:
```bash
uvicorn web.api:app --host 0.0.0.0 --port 8000 --reload
```

Интерактивная документация Swagger доступна по адресу:  
👉 **`http://localhost:8000/docs`**

| Метод | Эндпоинт | Описание |
| :--- | :--- | :--- |
| `GET` | `/health` | Проверка здоровья, статуса Ollama и конфигурации |
| `POST` | `/api/v1/scan/sast` | Запуск SAST аудита (локальная папка или GitHub репозиторий) |
| `POST` | `/api/v1/scan/dast` | Запуск DAST аудита веб-эндпоинтов (Headers, CORS, Cookies) |
| `POST` | `/api/v1/remediate` | Генерация AI-объяснения и безопасного патча |
| `POST` | `/api/v1/pr` | Автоматическое открытие Pull Request в GitHub |

---

## 🗺️ Roadmap

- [x] Архитектура ядра и Pydantic-конфигурация
- [x] Мульти-движковый SAST (Semgrep, Bandit, Pip-Audit, Python AST)
- [x] DAST проверка веб-эндпоинтов (CSP, HSTS, CORS, Cookies)
- [x] Локальный AI движок Remediation Engine на Ollama (`qwen2.5-coder:14b`) + Gemini Fallback
- [x] Автоматический генератор Pull Request на GitHub
- [x] Полнофункциональный Telegram-бот на `aiogram 3.x`
- [x] FastAPI REST API бэкенд
- [ ] React / Next.js Web Dashboard для визуализации отчетов в реальном времени
- [ ] Поддержка сканирования Dockerfile и Kubernetes манифестов

---

## 📄 Лицензия

Проект распространяется под свободной лицензией **MIT**. Подробности в файле [LICENSE](LICENSE).

<div align="center">
<b>Создано с 🖤 для безопасной разработки и вайбкодинга.</b>
</div>