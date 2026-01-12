<?php
declare(strict_types=1);

header('Content-Type: text/plain; charset=utf-8');

echo "=== ДИАГНОСТИКА ПОДКЛЮЧЕНИЯ К БАЗЕ ДАННЫХ ===\n\n";

$dbFile = __DIR__ . '/db.php';
if (!file_exists($dbFile)) {
  echo "ОШИБКА: Файл db.php не найден\n";
  echo "Ожидаемый путь: {$dbFile}\n";
  exit;
}
require_once $dbFile;
echo "db.php успешно подключён\n";

$envPath = dirname(__DIR__) . '/.env';
echo "\nПуть к .env:\n{$envPath}\n";

if (!file_exists($envPath)) {
  echo "ОШИБКА: Файл .env не найден\n";
  exit;
}
echo "Файл .env найден\n";

$vars = ['DB_HOST','DB_PORT','DB_NAME','DB_USER','DB_PASS'];

echo "\nПРОВЕРКА ПЕРЕМЕННЫХ ОКРУЖЕНИЯ:\n";

foreach ($vars as $v) {
  $val = getenv($v);
  if ($val === false || $val === '') {
    echo "{$v} — НЕ ЗАДАНА\n";
  } else {
    if ($v === 'DB_PASS') {
      echo "{$v} — задан (длина ".strlen($val).")\n";
    } else {
      echo "{$v} = {$val}\n";
    }
  }
}

echo "\nФОРМИРОВАНИЕ DSN:\n";

try {
  $dsn = sprintf(
    'mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
    getenv('DB_HOST'),
    (int)getenv('DB_PORT'),
    getenv('DB_NAME')
  );
  echo "DSN: {$dsn}\n";
} catch (Throwable $e) {
  echo "ОШИБКА формирования DSN: ".$e->getMessage()."\n";
  exit;
}

echo "\nПРОВЕРКА PDO ДРАЙВЕРОВ:\n";
$drivers = PDO::getAvailableDrivers();
echo "Доступные драйверы: ".implode(', ', $drivers)."\n";

if (!in_array('mysql', $drivers, true)) {
  echo "ОШИБКА: PDO MySQL не установлен на сервере\n";
  exit;
}
echo "PDO MySQL доступен\n";

echo "\nПОПЫТКА ПОДКЛЮЧЕНИЯ К БАЗЕ ДАННЫХ...\n";

try {
  $pdo = new PDO(
    $dsn,
    getenv('DB_USER'),
    getenv('DB_PASS'),
    [
      PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
      PDO::ATTR_TIMEOUT => 5,
    ]
  );

  echo "УСПЕШНОЕ ПОДКЛЮЧЕНИЕ К БАЗЕ ДАННЫХ\n";

  $v = $pdo->query("SELECT VERSION() AS v")->fetch();
  echo "Версия MySQL: ".$v['v']."\n";

  $db = $pdo->query("SELECT DATABASE() AS d")->fetch();
  echo "Текущая база данных: ".$db['d']."\n";

} catch (PDOException $e) {

  echo "\n ОШИБКА ПОДКЛЮЧЕНИЯ PDO\n";
  echo "Код ошибки: ".$e->getCode()."\n";
  echo "Сообщение: ".$e->getMessage()."\n\n";

  if (str_contains($e->getMessage(), 'Access denied')) {
    echo "ПРИЧИНА: Неверный логин или пароль пользователя БД\n";
  } elseif (str_contains($e->getMessage(), 'Unknown database')) {
    echo "ПРИЧИНА: Указанная база данных не существует\n";
  } elseif (str_contains($e->getMessage(), 'Connection refused')) {
    echo "ПРИЧИНА: Сервер БД отклонил соединение (порт закрыт или MySQL не слушает)\n";
  } elseif (str_contains($e->getMessage(), 'timed out')) {
    echo "ПРИЧИНА: Таймаут соединения (сервер БД недоступен с хостинга)\n";
  } elseif (str_contains($e->getMessage(), 'could not find driver')) {
    echo "ПРИЧИНА: На сервере отсутствует PDO MySQL драйвер\n";
  } else {
    echo "ПРИЧИНА: Неизвестная ошибка подключения\n";
  }

  exit;
}

echo "\n=== ДИАГНОСТИКА ЗАВЕРШЕНА ===\n";
