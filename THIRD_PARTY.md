# Сторонние компоненты

LICENSE в корне относится к собственному коду проекта (MIT). Сторонние компоненты сохраняют свои лицензии.

| Компонент | Версия / источник | Лицензия | Как используется |
|---|---|---|---|
| MagicProxy | `baf56b53edd360f3649a73a3695bd83432a32e7d`, <https://github.com/MagicMaxLabs/MagicProxy> | MIT, © 2026 MagicMax Labs (`third_party/MagicProxy/LICENSE`) | Пакеты `internal/config` и `internal/core` скопированы в `src/app/internal/` с изменениями (см. `docs/CHANGES-FROM-UPSTREAM.md`) |
| sing-box | v1.13.16, <https://github.com/SagerNet/sing-box/releases/tag/v1.13.16>; zip `sing-box-1.13.16-windows-amd64.zip`, SHA256 `6cbf90ec4ee87122ffce09b73928fb31e763bc1c75a119f79c61d24734c78807` | GPL-3.0-or-later + пункт про имя (`third_party/sing-box/`) | Поставляется **без изменений** как `bin\sing-box.exe`; запускается отдельным процессом. Соответствующий исходный код: <https://github.com/SagerNet/sing-box/tree/v1.13.16> (архив: <https://github.com/SagerNet/sing-box/archive/refs/tags/v1.13.16.tar.gz>). Текст GPL и уведомление лежат в `dist\runet-access\third_party\` |
| Go | 1.26.8 windows-amd64, <https://go.dev/dl/go1.26.8.windows-amd64.zip>, SHA256 `b92c3b2adae85a11ba71fe7216daf0d84e82af4c8ab6c5625807f28622043a59` | BSD-3-Clause | Только инструмент сборки (`.local\tools`); стандартная библиотека Go входит в бинарник хоста |
| Node.js | уже установлен на машине (v24.19.0) | MIT и др. | Только запуск тестов; в пакет не входит |
| Google Chrome | установлен пользователем | Собственная лицензия Google | Не поставляется; запускается как отдельный процесс с отдельным профилем |

Закреплённые версии и хеши проверяются скриптом `scripts/fetch-tools.ps1` (`scripts/tools.lock.json`).
Перед распространением пакета третьим лицам нужно убедиться, что вместе с ним передаётся этот файл,
тексты лицензий и ссылка на исходники sing-box (условие GPLv3 §6).
