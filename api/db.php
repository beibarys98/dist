<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
  http_response_code(204);
  exit;
}

$envPath = dirname(__DIR__, 1) . '/.env';

if (!file_exists($envPath)) {
  json_error('.env file not found', 500, 'env_missing');
}

$env = parse_ini_file($envPath, false, INI_SCANNER_RAW);
if ($env === false) {
  json_error('Failed to parse .env file', 500, 'env_parse_error');
}

foreach ($env as $key => $value) {
  if (getenv($key) === false) {
    putenv("$key=$value");
    $_ENV[$key] = $value;
  }
}

function env(string $key): string {
  $value = getenv($key);
  if ($value === false || $value === '') {
    json_error("Missing env variable: {$key}", 500, 'env_error');
  }
  return $value;
}


function db(): PDO {
    $dsn = sprintf(
        'mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
        getenv('DB_HOST'),
        (int) getenv('DB_PORT'),
        getenv('DB_NAME')
    );

    try {
        return new PDO(
            $dsn,
            getenv('DB_USER'),
            getenv('DB_PASS'),
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]
        );
    } catch (Throwable $e) {
        echo json_encode([
            'error' => 'db_connect_error',
            'message' => $e->getMessage()
        ]);
        exit;
    }
}

function json_error(string $message, int $code = 500, string $error = 'server_error'): void {
  http_response_code($code);
  echo json_encode([
    'error'   => $error,
    'message'=> $message
  ], JSON_UNESCAPED_UNICODE);
  exit;
}

function get_lang(): string {
  $lang = strtolower((string)($_GET['lang'] ?? 'ru'));
  return in_array($lang, ['ru','kk','en'], true) ? $lang : 'ru';
}

function get_int(string $key, int $default = 0): int {
  return isset($_GET[$key]) ? (int)$_GET[$key] : $default;
}
