# CertBlocker-NoAdmin

Версия [CertBlocker](https://github.com/1565gfd/CertBlocker), не требующая прав
администратора. Помечает сертификат недоверенным для **текущего пользователя**,
добавляя его в хранилище `CurrentUser\Disallowed`. UAC не запрашивается, доступ к
Настройкам Windows не нужен.

![platform](https://img.shields.io/badge/platform-Windows%207–11-0078D6?logo=windows&logoColor=white)
![framework](https://img.shields.io/badge/.NET%20Framework-4.x-512BD4)
![admin](https://img.shields.io/badge/admin-not%20required-2ECC71)
![license](https://img.shields.io/badge/license-MIT-2ECC71)

![Скриншот](docs/screenshot.png)

## Возможности

- Блокировка сертификата из файла (`.cer`, `.crt`, `.der`, `.pem`).
- Поиск установленных корневых сертификатов и блокировка выбранного.
- Просмотр и разблокировка ранее заблокированных сертификатов.
- Экспорт сертификата в `.cer`.

## Отличие от основной версии

Блокировка применяется только к текущей учётной записи Windows (`CurrentUser`),
а не ко всей системе. Взамен не требуются права администратора.

## Требования

- Windows 7–11.
- .NET Framework 4.x (входит в состав Windows).

## Сборка

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

## Проверка целостности

```powershell
Get-FileHash -Algorithm SHA256 .\CertBlocker-NoAdmin.exe
```

SHA-256 релиза **v1.0.2**:

```
D6E2B38E1D57A9C287BEC9C6570202C12DC0F16F1B6B3EA91F434E0E62DAE41A
```

## Примечания

- Приложение не подписано — возможно предупреждение SmartScreen при первом запуске.
- Единственное изменение — запись в хранилище `CurrentUser\Disallowed`, обратимая
  кнопкой «Разблокировать». Сеть не используется, внешние процессы не запускаются.

## Лицензия

[MIT](LICENSE)
