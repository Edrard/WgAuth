# WgAuth

Незалежна PHP-бібліотека авторизації World of Tanks для EU, NA та ASIA. Підтримує вхід через браузер, одноразовий state, перевірку власника токена, оновлення та відкликання токена. Користувачів і сесії застосунку створює сам застосунок.

Канонічна документація англійською: [README.md](../../README.md).

## Встановлення та налаштування

Поточний код WgAuth залежить від `edrard/wgapi: dev-master`. Для цих змін застосунок має явно вимагати `edrard/wgauth: dev-main` і `edrard/wgapi: dev-master` у кореневому `composer.json`; приклад наведено в англійському README. Глобальне `minimum-stability` змінювати не потрібно. Тег v1.0.3 зберігає попередню залежність WgApi `^2.0`. `composer install` використовує зафіксовані коміти з lock; для оновлення цих гілок виконайте `composer update edrard/wgauth edrard/wgapi --minimal-changes --prefer-stable`.

Потрібні PHP 8.5, Composer 2, розширення ctype, filter та session. Для локальної розробки виконайте `composer install` у каталозі бібліотеки. Для встановлення у застосунок оголосіть VCS-репозиторії WgAuth та WgApi у кореневому `composer.json`, як показано в англійській документації. Поточна версія для встановлення — `dev-main`; вона містить необов'язкове PSR-3 логування.

```php
use edrard\WgApi\Realm;
use edrard\WgAuth\AuthClient;
use edrard\WgAuth\Session\PhpSessionStateStore;
use edrard\WgAuth\WgAuth;

require __DIR__.'/vendor/autoload.php';

$applicationId = getenv('WG_APPLICATION_ID');
if (!$applicationId) {
    throw new LogicException('Configure WG_APPLICATION_ID.');
}
$client = new AuthClient($applicationId);
session_start([
    'use_strict_mode' => true,
    'cookie_secure' => true,
    'cookie_httponly' => true,
    'cookie_samesite' => 'Lax',
]);
$auth = new WgAuth($client, new PhpSessionStateStore());
$location = $auth->beginLogin(Realm::EU, 'https://your-app.example/auth/wargaming/callback');
```

Callback URI задається довіреною конфігурацією. Застосунок перенаправляє браузер на `$location`, а на callback викликає `$auth->completeLogin($_GET)`. Тримайте серверну сесію активною до завершення перевірки. State споживається одноразово навіть за невдалого входу. Для Laravel реалізуйте `StateStoreInterface` через сесію застосунку з атомарним споживанням і прив'язкою до браузера.

`$client->prolongate($token)` повертає новий токен; `$client->logout($token)` відкликає токен WG. Автоматичних повторів запитів немає. Токени та callback query не повинні потрапляти до журналів застосунку, вебсервера чи APM.

## Необов'язкове логування

Без зовнішнього логера бібліотека працює через `Psr\Log\NullLogger`. Для підключення будь-якого PSR-3 логера, налаштованого застосунком:

```php
$client = new AuthClient($applicationId, logger: $logger);
$auth = new WgAuth($client, new PhpSessionStateStore(), logger: $logger);
```

`AuthClient` передає логер типовому `GuzzleAuthTransport`. Власний транспорт налаштовується окремо, наприклад `new GuzzleAuthTransport($httpClient, logger: $logger)`.

Завершення входу, оновлення/відкликання токена, відхилення state, скасування входу та відмова провайдера мають рівень `debug`. Збої транспорту, HTTP-помилки, некоректні відповіді та невдала перевірка власника мають рівень `warning`. Один збій не дублюється на вищих рівнях. Звичайне отримання URL входу та успішна перевірка власника не створюють записів. Помилки аргументів, розбору/строку дії токена та власних сховищ/транспортів обробляються наявними винятками без додаткових записів.

Контекст містить лише регіон або числовий HTTP-статус. Токени, application ID, state, URL, тіла запитів/відповідей, account ID, nickname та сирі винятки не передаються логеру. Винятки можуть містити секрети в повідомленнях і трасуванні.

Якщо логер кидає `Throwable`, запис відкидається: результат, початковий виняток і споживання state не змінюються. Повторної доставки немає. Бібліотека не налаштовує файли, рівні, ротацію чи часові пояси. PSR-3 синхронний; для неблокуючої доставки застосунок має надати відповідний логер.

## Перевірки

```sh
composer test
composer analyse
composer format:check
composer validate --strict
```

Форматування: `composer format` (налаштований PHP CS Fixer, PSR-12). Приклади HTTPS-входу та добровільної живої перевірки регіонів описано в англійському README. Живі запити не є частиною локальних тестів.
