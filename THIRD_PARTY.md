# Сторонние компоненты

LICENSE в корне относится к собственному коду проекта (MIT). Сторонние компоненты сохраняют свои лицензии.

| Компонент | Версия / источник | Лицензия | Как используется |
|---|---|---|---|
| MagicProxy | `baf56b53edd360f3649a73a3695bd83432a32e7d`, <https://github.com/MagicMaxLabs/MagicProxy> | MIT, © 2026 MagicMax Labs (`third_party/MagicProxy/LICENSE`) | Пакеты `internal/config` и `internal/core` скопированы в `src/app/internal/` с изменениями (см. `docs/CHANGES-FROM-UPSTREAM.md`) |
| sing-box | v1.13.16, <https://github.com/SagerNet/sing-box/releases/tag/v1.13.16>; zip `sing-box-1.13.16-windows-amd64.zip`, SHA256 `6cbf90ec4ee87122ffce09b73928fb31e763bc1c75a119f79c61d24734c78807` | GPL-3.0-or-later + пункт про имя (`third_party/sing-box/`) | Поставляется **без изменений** как `sing-box.exe` рядом с `RunetAccess.exe`; запускается отдельным процессом. Лицензии и **исходный код** лежат в установленной папке `licenses\sing-box\`: GPL-3.0, LICENSE, архив исходников точной версии (`sing-box-1.13.16-source.tar.gz`, SHA256 `5d8201669387d0caded7a22c71682b3c025afef7bac8704cceabed52ea8bde5d`), письменное предложение на исходники зависимостей (`SOURCE-OFFER.txt`, GPLv3 §6b). Полный комплект с зависимостями (около 440 МБ в архиве) собирает `scripts\make-source-offer.ps1` |
| Go | 1.26.8 windows-amd64, <https://go.dev/dl/go1.26.8.windows-amd64.zip>, SHA256 `b92c3b2adae85a11ba71fe7216daf0d84e82af4c8ab6c5625807f28622043a59` | BSD-3-Clause | Только инструмент сборки (`.local\tools`); стандартная библиотека Go входит в бинарник хоста |
| Outline SDK (`golang.getoutline.org/sdk`) | v0.0.23, <https://github.com/OutlineFoundation/outline-sdk> (прежде Jigsaw-Code/outline-sdk); хеш модуля `h1:UKoKCrRH3Ed6Jpg8ODYwOo6O1B1lvfIHPreMrTkSTcc=` совпадает с базой контрольных сумм Go (sum.golang.org) | Apache-2.0 (`third_party/outline-sdk/LICENSE`) | Библиотека, **без изменений**, компилируется в `RunetAccess.exe` (пакеты `transport`, `transport/shadowsocks`). Нужна для «префикса» Outline: sing-box 1.13.16 не умеет задавать начало соли Shadowsocks. Используется только для ключей с префиксом (`internal/ssbridge`) |
| go-shadowsocks2 (пакет `socks`) | v0.1.5, <https://github.com/shadowsocks/go-shadowsocks2>, `h1:PDSQv9y2S85Fl7VBeOMF9StzeXZyK1HakRm86CUbr28=` | Apache-2.0 (`third_party/go-shadowsocks2/LICENSE`) | Зависимость Outline SDK (разбор адреса назначения), компилируется в `RunetAccess.exe` |
| golang.org/x/crypto, golang.org/x/sys | v0.41.0 и v0.35.0, `h1:WKYxWedPGCTVVl5+WHSSrOBT0O8lx32+zxmHxijgXp4=`, `h1:vz1N37gP5bs89s7He8XuIYXpyY0+QlsKmzipCbUtyxI=` | BSD-3-Clause + патентное разрешение Go (`third_party/golang-x/`) | Зависимости Outline SDK (шифры AEAD), компилируются в `RunetAccess.exe` |
| Node.js | уже установлен на машине (v24.19.0) | MIT и др. | Только запуск тестов; в пакет не входит |
| Inno Setup | 6.7.3, <https://github.com/jrsoftware/issrc/releases/tag/is-6_7_3>, SHA256 `9c73c3bae7ed48d44112a0f48e66742c00090bdb5bef71d9d3c056c66e97b732`, подпись Authenticode (Pyrsys B.V.) | Лицензия Inno Setup (<https://jrsoftware.org/files/is/license.txt>) | Только компилятор установщика (`.local	ools\innosetup`); в пакет не входит, но заготовка установщика (Setup stub) входит в `Setup.exe` |
| Google Chrome | установлен пользователем | Собственная лицензия Google | Не поставляется; запускается как отдельный процесс с отдельным профилем |

Закреплённые версии и хеши проверяются скриптами `scripts/fetch-tools.ps1` и `scripts/make-installer.ps1` (`scripts/tools.lock.json`):
установщик не собирается, если sing-box не совпал с закреплённым выпуском или архив исходников не совпал по хешу.
Состав каждого установщика (файлы, хеши, коммит Git, версии компонентов) пишется в `BUILD-INFO` и `*.contents.txt`.
