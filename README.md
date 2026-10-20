# state-forge

[![CI](https://github.com/pochemu-august/state-forge/actions/workflows/ci.yml/badge.svg)](https://github.com/pochemu-august/state-forge/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-informational.svg)](Cargo.toml)
[![Rust](https://img.shields.io/badge/rust-edition%202024-orange.svg)](Cargo.toml)

> **state-forge** — высокопроизводительная утилита на Rust для мониторинга сетевой активности процессов Windows, низкоуровневого перехвата Winsock API, анализа протоколов (выявления состояний и переходов) и автоматической генерации stateful mock-серверов на базе **Axum / Tokio**.

---

## Архитектура Фазы 1: Winsock Interceptor

```
[ Целевой процесс (Target.exe) ]
    │
    └── Внедренная DLL: state_forge_hook.dll
          ├── MinHook: перехват функций ws2_32.dll (connect, send, recv, closesocket)
          └── IPC Клиент: сериализация и отправка сырых буферов
                │
                ▼ (Windows Named Pipe: \\.\pipe\state_forge_<PID>)
[ state-forge CLI (Tokio Orchestrator) ]
    ├── Injector: выделение памяти и запуск LoadLibraryW через CreateRemoteThread
    ├── Named Pipe Server: чтение бинарных фреймов bincode
    ├── Tokio mpsc Channel: асинхронная очередь событий
    └── Event Logger: структурированное логирование с Hex-дампом и ASCII-превью
```

---

## Структура репозитория

```text
state-forge/
├── .github/workflows/ci.yml     # GitHub Actions CI (Windows x64)
├── crates/
│   ├── state-forge-common/      # Общие структуры IPC-событий (Serde / Bincode)
│   ├── state-forge-hook/        # cdylib: хуки Winsock и клиент Named Pipe
│   ├── state-forge-injector/    # DLL инжектор (CreateRemoteThread / LoadLibraryW)
│   ├── state-forge-cli/         # Главный бинарник CLI (Tokio Named Pipe Server)
│   └── test-target/             # Демонстрационный TCP-клиент для тестирования
├── analyze.bat                  # Скрипт полного аудита качества кода и запуска
├── LICENSE                      # MIT License
└── README.md
```

---

## Быстрый старт

### Требования
- ОС: **Windows 10 / 11 (x64)**
- Инструменты: **Rust 1.85+** (MSVC toolchain)

### 1. Сборка всего воркспейса
```cmd
cargo build --workspace
```

### 2. Запуск в интерактивном режиме (Demo)
Скрипт автоматически соберет проект и предложит запустить тестовый процесс `test-target`:
```cmd
analyze.bat run
```

### 3. Ручной запуск перехвата существующего процесса
```cmd
cargo run -p state-forge-cli -- <PID>
```
Или через скрипт:
```cmd
analyze.bat run <PID>
```

---

## Проверка и аудит качества кода

Скрипт [`analyze.bat`](analyze.bat) выполняет автоматический анализ форматирования, линтинг, компиляцию целей и тесты, сохраняя детальные отчеты в `logs/`:
```cmd
analyze.bat
```

Проверяемые этапы:
1. **Стиль кода**: `cargo fmt --all -- --check` $\rightarrow$ `logs\fmt.log`
2. **Логика и качество**: `cargo clippy --workspace --all-targets --all-features` $\rightarrow$ `logs\clippy.log`
3. **Проверка компиляции**: `cargo check --workspace --all-targets` $\rightarrow$ `logs\check.log`
4. **Тесты**: `cargo test --workspace` $\rightarrow$ `logs\test.log`

---

## Roadmap

- [x] **Фаза 1: User-mode Winsock Hook & Tokio Orchestrator**
  - [x] Перехват `connect`, `send`, `recv`, `closesocket` в `ws2_32.dll`.
  - [x] Высокоскоростной IPC через Windows Named Pipes.
  - [x] Асинхронное логирование и Hex/ASCII-дамп пакетов.
- [ ] **Фаза 2: Анализ протокола и State Machine Reconstruction**
  - [ ] Выравнивание и парсинг потоковых фреймов (framing / delimiting).
  - [ ] Автоматическое построение графа состояний (диалог Client $\leftrightarrow$ Server).
  - [ ] Детекция динамических полей (session ID, timestamp, nonces).
- [ ] **Фаза 3: Генерация Stateful Mock Server**
  - [ ] Автоматическая кодогенерация проекта на Axum / Tokio.
  - [ ] Воспроизведение сценариев и эмуляция сетевых задержек/ошибок.

---

## Лицензия

Проект распространяется под лицензией [MIT](LICENSE).
