<div align="center">

# 🛡️ CyberSecurityBot
### Autonomous Local AI Pentester & DevSecOps Remediation Assistant

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
[![aiogram 3.x](https://img.shields.io/badge/Telegram-aiogram%203.x-2CA5E0.svg?style=for-the-badge&logo=telegram)](https://aiogram.dev/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111%2B-009688.svg?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Ollama](https://img.shields.io/badge/Ollama-100%25%20Local%20AI-black.svg?style=for-the-badge&logo=ollama)](https://ollama.ai/)
[![Strix Engine](https://img.shields.io/badge/Deep%20Pentest-Strix%20Engine-orange.svg?style=for-the-badge)](https://github.com/usestrix/strix)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

<p align="center">
  <b>Автономный AI-ассистент для поиска уязвимостей, валидации эксплойтов и автоматического создания Pull Request с безопасным кодом прямо в Telegram.</b>
</p>

<!-- МЕСТО ДЛЯ ГИФКИ РАБОТЫ БОТА -->
<img src="assets/demo.gif" alt="CyberSecurityBot Telegram Demo" width="800px" style="border-radius: 12px; box-shadow: 0 8px 24px rgba(0,0,0,0.2);" />

[Ключевые возможности](#-ключевые-возможности) • [Архитектура](#-архитектура) • [Быстрый старт](#-быстрый-старт) • [Сценарий в Telegram](#-сценарий-работы-в-telegram) • [REST API](#-fastapi-эндпоинты) • [Roadmap](#-roadmap)

</div>

---

## 🌟 Зачем нужен CyberSecurityBot?

В эпоху быстрой разработки и вайбкодинга проекты часто выходят в продакшн с критическими багами (утечки API-ключей, SQL-инъекции, `eval()`, открытые Firestore rules, ошибки CORS и IDOR).

**CyberSecurityBot** решает эту задачу в 4 шага:
1. 🔐 **Proof of Ownership** — строгая верификация авторства репозитория перед сканированием.
2. 🔍 **Мульти-аудит (SAST + DAST + Strix Pentest)** — поиск дефектов за 0.5 сек или глубокий агентный анализ.
3. 🧠 **Приватный локальный AI (Ollama)** — генерация объяснения и безопасного патча без утечки кода в облако.
4. 🚀 **Auto-PR** — открытие готового Pull Request на GitHub в один клик.

> **Deep Scanning powered by Strix Engine (Apache 2.0)**

---

## ⚡ Ключевые возможности

| Функция | Описание |
| :--- | :--- |
| 🔐 **Proof of Ownership** | Двухфакторная проверка владения: **GitHub Access Token** или **Commit Challenge** (без передачи токена). |
| ⚡ **Multi-Language SAST** | Статический анализ Flutter/Dart, Python AST, JS/TS, Firestore Rules, `.env` и секретов. |
| 🤖 **Deep AI Pentest (Strix)** | Агентный глубокий пентест бизнес-логики, IDOR и цепочек атак на базе открытого движка **Strix**. |
| 🌐 **Dynamic Auditor (DAST)** | Фаззинг заголовков безопасности (CSP, HSTS, X-Frame-Options), CORS и cookie-флагов. |
| 🧪 **Exploit PoC & cURL Test** | Автоматическая генерация проверочного cURL-запроса и валидация на тестовом стенде. |
| 🧠 **100% Local AI Remediation** | Работа на базе локальной модели `qwen2.5-coder:14b` через Ollama (с гибридным fallback на Gemini). |
| 🚀 **Auto-PR Generator** | Создание изолированной ветки `security-fix/...` и открытие оформленного Pull Request на GitHub. |
| 📄 **Экспорт Markdown-отчетов** | Скачивание подробного структурированного аудиторского отчета прямо в Telegram. |

---

## 🏛 Архитектура

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │                      INTERFACES / ENTRYPOINTS                          │
 │       Telegram Bot (aiogram 3.x)   │    FastAPI Web Dashboard / CLI    │
 └───────────────────────────────────┬────────────────────────────────────┘
                                     │
                    [ 1. Proof of Ownership Verification ]
                                     │
           ┌─────────────────────────┼────────────────────────┐
           ▼                         ▼                        ▼
 ┌───────────────────┐    ┌────────────────────┐   ┌────────────────────┐
 │     FAST SAST     │    │    DAST ENGINE     │   │ STRIX DEEP PENTEST │
 │ • Multi-Lang AST  │    │ • CSP / HSTS       │   │ • Multi-Agent Recon│
 │ • Semgrep & Bandit│    │ • CORS Reflection  │   │ • Logic & IDOR Flaw│
 │ • Pip-Audit CVEs  │    │ • Cookie Auditing  │   │ • (Apache-2.0)     │
 └─────────┬─────────┘    └──────────┬─────────┘   └─────────┬──────────┘
           │                         │                       │
           └─────────────────────────┼───────────────────────┘
                                     ▼
                       [ Normalized Findings JSON ]
                                     │
                                     ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                       AI REMEDIATION ENGINE                            │
 │  • Local Ollama (qwen2.5-coder:14b on Apple Silicon M-Series)          │
 │  • Hybrid Cloud Fallback (Google Gemini 2.5 Flash API)                 │
 └───────────────────────────────────┬────────────────────────────────────┘
                                     │
                    [ Exploit PoC & Patch Generated ]
                                     │
                                     ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                     AUTOMATED PULL REQUEST ENGINE                      │
 │    Creates Branch -> Applies Code -> Opens GitHub PR with Summary      │
 └────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Быстрый старт

### 1. Клонирование и зависимости

```bash
git clone https://github.com/madiyarmoldakhmet-ai/cybersecyritybot.git
cd cybersecuritybot

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Настройка переменных окружения

```bash
cp .env.example .env
```

Заполните `.env`:
```env
# Telegram Bot Token (от @BotFather)
TELEGRAM_BOT_TOKEN=123456789:ABCdef...

# Локальный AI Движок (Ollama)
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5-coder:14b

# (Опционально) Облачный Fallback
GEMINI_API_KEY=your_gemini_api_key
```

### 3. Запуск локальной LLM

```bash
ollama run qwen2.5-coder:14b
```

### 4. Запуск Telegram-бота

```bash
python3 -m bot.main
```

---

## 📱 Сценарий работы в Telegram

1. **Запуск**: Отправьте `/start` и выберите способ подтверждения владения:
   * **GitHub Token** — мгновенный доступ и Auto-PR.
   * **Commit Challenge** — безопасная верификация через разовый коммит.
2. **Выбор режима сканирования**:
   * ⚡ **Быстрый SAST-скан (0.5 сек)**
   * 🤖 **Deep AI Pentest (Strix, 1-3 мин)**
3. **Анализ уязвимостей**:
   * Нажмите **«🧪 Сгенерировать проверочный запрос»** для получения cURL-команды.
   * Нажмите **«🚀 Запустить проверку»** для тестирования целевого URL.
4. **Устранение**:
   * Нажмите **«🤖 Сгенерировать AI-исправление и PR»** — бот автоматически откроет Pull Request на GitHub!

---

## 🌐 FastAPI эндпоинты

Запуск REST API:
```bash
uvicorn web.api:app --host 0.0.0.0 --port 8000 --reload
```
Документация Swagger доступна по адресу: `http://localhost:8000/docs`.

---

## 📄 Лицензия

Проект распространяется под лицензией **MIT** (см. [LICENSE](LICENSE)).  
*Deep Scanning powered by Strix Engine (Apache 2.0).*