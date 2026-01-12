<?php
declare(strict_types=1);

header('Content-Type: text/html; charset=utf-8');
ini_set('display_errors', '0');
error_reporting(E_ALL);

function load_env(string $path): void {
  if (!is_file($path)) return;
  $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
  if (!$lines) return;

  foreach ($lines as $line) {
    $line = trim($line);
    if ($line === '' || str_starts_with($line, '#')) continue;
    $pos = strpos($line, '=');
    if ($pos === false) continue;

    $key = trim(substr($line, 0, $pos));
    $val = trim(substr($line, $pos + 1));
    if ($key === '') continue;

    if ((str_starts_with($val, '"') && str_ends_with($val, '"')) ||
        (str_starts_with($val, "'") && str_ends_with($val, "'"))) {
      $val = substr($val, 1, -1);
    }

    if (getenv($key) === false) {
      putenv($key . '=' . $val);
      $_ENV[$key] = $val;
    }
  }
}
load_env(__DIR__ . '/.env');

function e(string $s): string { return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function now(): int { return time(); }

function env(string $k, string $default = ''): string {
  $v = getenv($k);
  return ($v === false || $v === '') ? $default : (string)$v;
}
function env_int(string $k, int $default): int {
  $v = getenv($k);
  if ($v === false || $v === '') return $default;
  return (int)$v;
}
function require_env(string $k): string {
  $v = env($k, '');
  if ($v === '') {
    http_response_code(500);
    echo "Server misconfigured: missing env {$k}";
    exit;
  }
  return $v;
}

function is_probably_url(string $s): bool {
  $s = trim($s);
  return (str_starts_with($s, 'http://') || str_starts_with($s, 'https://'));
}

function db(): PDO {
  static $pdo = null;
  if ($pdo instanceof PDO) return $pdo;

  $DB_HOST = require_env('DB_HOST');
  $DB_PORT = env_int('DB_PORT', 3306);
  $DB_NAME = require_env('DB_NAME');
  $DB_USER = require_env('DB_USER');
  $DB_PASS = require_env('DB_PASS');

  $dsn = "mysql:host={$DB_HOST};port={$DB_PORT};dbname={$DB_NAME};charset=utf8mb4";
  $pdo = new PDO($dsn, $DB_USER, $DB_PASS, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
  ]);
  return $pdo;
}

function b64url_encode(string $s): string {
  return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
}
function b64url_decode(string $s): string {
  $s = strtr($s, '-_', '+/');
  $pad = strlen($s) % 4;
  if ($pad) $s .= str_repeat('=', 4 - $pad);
  $out = base64_decode($s, true);
  return $out === false ? '' : $out;
}
function sign_payload(string $payload, string $secret): string {
  return hash_hmac('sha256', $payload, $secret, true);
}
function set_admin_cookie(string $user, int $ttl, string $secret): void {
  $exp = now() + $ttl;
  $nonce = bin2hex(random_bytes(8));
  $payload = $user . '|' . $exp . '|' . $nonce;
  $sig = sign_payload($payload, $secret);
  $token = b64url_encode($payload) . '.' . b64url_encode($sig);

  setcookie('admin_token', $token, [
    'expires' => $exp,
    'path' => '/',
    'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
    'httponly' => true,
    'samesite' => 'Lax',
  ]);
}
function clear_admin_cookie(): void {
  setcookie('admin_token', '', [
    'expires' => 1,
    'path' => '/',
    'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
    'httponly' => true,
    'samesite' => 'Lax',
  ]);
}
function is_admin_authed(string $userExpected, string $secret): bool {
  $t = (string)($_COOKIE['admin_token'] ?? '');
  if ($t === '' || strpos($t, '.') === false) return false;

  [$p64, $s64] = explode('.', $t, 2);
  $payload = b64url_decode($p64);
  $sig = b64url_decode($s64);
  if ($payload === '' || $sig === '') return false;

  $calc = sign_payload($payload, $secret);
  if (!hash_equals($calc, $sig)) return false;

  $parts = explode('|', $payload);
  if (count($parts) !== 3) return false;

  $user = (string)$parts[0];
  $exp  = (int)$parts[1];

  if ($user !== $userExpected) return false;
  if ($exp < now()) return false;

  return true;
}

function get_csrf_secret(): string {
  return hash('sha256', require_env('ADMIN_SECRET') . '|csrf', true);
}
function set_csrf_cookie(): void {
  $token = bin2hex(random_bytes(16));
  $sig = sign_payload($token, get_csrf_secret());
  $val = b64url_encode($token) . '.' . b64url_encode($sig);

  setcookie('csrf_token', $val, [
    'expires' => now() + 86400,
    'path' => '/',
    'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
    'httponly' => true,
    'samesite' => 'Lax',
  ]);
}
function read_csrf_token(): string {
  $c = (string)($_COOKIE['csrf_token'] ?? '');
  if ($c === '' || strpos($c, '.') === false) return '';
  [$t64, $s64] = explode('.', $c, 2);
  $t = b64url_decode($t64);
  $s = b64url_decode($s64);
  if ($t === '' || $s === '') return '';
  $calc = sign_payload($t, get_csrf_secret());
  if (!hash_equals($calc, $s)) return '';
  return $t;
}
function csrf_field(): string {
  $t = read_csrf_token();
  if ($t === '') { set_csrf_cookie(); $t = read_csrf_token(); }
  return '<input type="hidden" name="csrf" value="'.e($t).'">';
}
function csrf_check(): void {
  $cookieToken = read_csrf_token();
  $postToken = (string)($_POST['csrf'] ?? '');
  if ($cookieToken === '' || $postToken === '' || !hash_equals($cookieToken, $postToken)) {
    http_response_code(400);
    exit('Bad CSRF token');
  }
}

function to_datetime_local(string $mysql): string {
  $mysql = trim($mysql);
  if ($mysql === '') return '';
  if (!preg_match('~^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}$~', $mysql)) return '';
  return str_replace(' ', 'T', substr($mysql, 0, 16));
}
function from_datetime_local(string $local): ?string {
  $local = trim($local);
  if ($local === '') return null;
  if (!preg_match('~^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$~', $local)) return null;
  $local = str_replace('T', ' ', $local);
  if (strlen($local) === 16) $local .= ':00';
  return $local;
}

function table_exists(PDO $pdo, string $table): bool {
  try { $pdo->query("SELECT 1 FROM `$table` LIMIT 1"); return true; }
  catch (Throwable $e) { return false; }
}
function columns(PDO $pdo, string $table): array {
  $cols = [];
  $st = $pdo->query("SHOW COLUMNS FROM `$table`");
  foreach ($st->fetchAll() as $r) $cols[$r['Field']] = true;
  return $cols;
}
function val(array $row, string $k): string { return isset($row[$k]) ? (string)$row[$k] : ''; }

function php_bytes(string $val): int {
  $val = trim($val);
  if ($val === '') return 0;
  $last = strtolower($val[strlen($val)-1]);
  $num = (int)$val;
  return match ($last) {
    'g' => $num * 1024 * 1024 * 1024,
    'm' => $num * 1024 * 1024,
    'k' => $num * 1024,
    default => (int)$val,
  };
}
function fmt_bytes(int $b): string {
  if ($b <= 0) return '0';
  $u = ['B','KB','MB','GB','TB'];
  $i = 0;
  $x = (float)$b;
  while ($x >= 1024 && $i < count($u)-1) { $x/=1024; $i++; }
  return rtrim(rtrim(number_format($x, 2, '.', ''), '0'), '.') . ' ' . $u[$i];
}

function flash_set(string $key, string $msg): void {
  $payload = b64url_encode($msg);
  setcookie("flash_{$key}", $payload, [
    'expires' => now() + 120,
    'path' => '/',
    'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
    'httponly' => false,
    'samesite' => 'Lax',
  ]);
}
function flash_get(string $key): string {
  $c = (string)($_COOKIE["flash_{$key}"] ?? '');
  if ($c === '') return '';
  // Clear immediately
  setcookie("flash_{$key}", '', [
    'expires' => 1,
    'path' => '/',
    'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
    'httponly' => false,
    'samesite' => 'Lax',
  ]);
  return b64url_decode($c);
}

function delete_media_file(string $filePath, string $uploadUrl, string $uploadDir): void {
  $uploadUrl = rtrim($uploadUrl, '/');
  if ($filePath === '') return;

  if (str_starts_with($filePath, $uploadUrl . '/')) {
    $fileName = substr($filePath, strlen($uploadUrl) + 1);
    $abs = rtrim($uploadDir, '/\\') . DIRECTORY_SEPARATOR . $fileName;
    if (is_file($abs)) @unlink($abs);
  }
}

function upload_err_text(int $code): string {
  return match ($code) {
    UPLOAD_ERR_OK => 'OK',
    UPLOAD_ERR_INI_SIZE => 'UPLOAD_ERR_INI_SIZE (upload_max_filesize)',
    UPLOAD_ERR_FORM_SIZE => 'UPLOAD_ERR_FORM_SIZE',
    UPLOAD_ERR_PARTIAL => 'UPLOAD_ERR_PARTIAL',
    UPLOAD_ERR_NO_FILE => 'UPLOAD_ERR_NO_FILE',
    UPLOAD_ERR_NO_TMP_DIR => 'UPLOAD_ERR_NO_TMP_DIR',
    UPLOAD_ERR_CANT_WRITE => 'UPLOAD_ERR_CANT_WRITE',
    UPLOAD_ERR_EXTENSION => 'UPLOAD_ERR_EXTENSION',
    default => 'UNKNOWN_ERROR_'.$code,
  };
}

function guess_type_by_ext(string $ext): string {
  $ext = strtolower($ext);
  $img = ['jpg','jpeg','png','webp','gif','heic','heif'];
  $vid = ['mp4','mov'];
  if (in_array($ext, $img, true)) return 'image';
  if (in_array($ext, $vid, true)) return 'video';
  return 'file';
}

function save_uploaded_media(PDO $pdo, int $newsId, string $uploadDir, string $uploadUrl, bool $hasNewsMedia, array $mediaCols): array {
  $result = [
    'received' => 0,
    'saved' => 0,
    'errors' => [], 
  ];

  if (empty($_FILES['media']) || !is_array($_FILES['media']['name'])) {
    return $result;
  }

  $allowedExt = ['jpg','jpeg','png','webp','gif','heic','heif','mp4','mov','pdf'];
  $maxBytes = 25 * 1024 * 1024;

  $iniUpload = php_bytes((string)ini_get('upload_max_filesize'));
  $iniPost   = php_bytes((string)ini_get('post_max_size'));
  $iniMaxFiles = (int)ini_get('max_file_uploads');

  if (!is_dir($uploadDir)) @mkdir($uploadDir, 0755, true);
  if (!is_dir($uploadDir) || !is_writable($uploadDir)) {
    $msg = "Папка загрузки недоступна для записи: {$uploadDir}";
    error_log("UPLOAD: {$msg}");
    $result['errors'][] = $msg;
    return $result;
  }

  $count = count($_FILES['media']['name']);
  $result['received'] = $count;

  $nextSort = 0;
  if ($hasNewsMedia && isset($mediaCols['sort_order'])) {
    try {
      $st = $pdo->prepare("SELECT COALESCE(MAX(sort_order),0) AS m FROM news_media WHERE news_id=?");
      $st->execute([$newsId]);
      $row = $st->fetch();
      $nextSort = (int)($row['m'] ?? 0);
    } catch (Throwable $e) {
      $nextSort = 0;
    }
  }

  for ($i=0; $i<$count; $i++) {
    $err  = (int)($_FILES['media']['error'][$i] ?? UPLOAD_ERR_NO_FILE);
    $tmp  = (string)($_FILES['media']['tmp_name'][$i] ?? '');
    $name = (string)($_FILES['media']['name'][$i] ?? '');
    $mime = (string)($_FILES['media']['type'][$i] ?? '');
    $size = (int)($_FILES['media']['size'][$i] ?? 0);

    if ($err !== UPLOAD_ERR_OK) {
      $text = upload_err_text($err);
      error_log("UPLOAD: file #{$i} '{$name}' error={$err} {$text}");
      if ($err === UPLOAD_ERR_INI_SIZE || $err === UPLOAD_ERR_FORM_SIZE) {
        $result['errors'][] =
          "Файл '{$name}' слишком большой. Лимиты сервера: upload_max_filesize=" . (string)ini_get('upload_max_filesize') .
          ", post_max_size=" . (string)ini_get('post_max_size') .
          ", max_file_uploads={$iniMaxFiles}.";
      }
      continue;
    }

    if ($size <= 0) {
      error_log("UPLOAD: file #{$i} '{$name}' size=0");
      $result['errors'][] = "Файл '{$name}' пустой или не прочитан.";
      continue;
    }

    if ($size > $maxBytes) {
      error_log("UPLOAD: file #{$i} '{$name}' too big size={$size} max={$maxBytes}");
      $result['errors'][] = "Файл '{$name}' больше " . fmt_bytes($maxBytes) . ".";
      continue;
    }

    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    if ($ext === '' || !in_array($ext, $allowedExt, true)) {
      error_log("UPLOAD: file #{$i} '{$name}' rejected ext='{$ext}' mime='{$mime}'");
      $result['errors'][] = "Файл '{$name}' не поддерживается (расширение: {$ext}).";
      continue;
    }

    if ($tmp === '' || !is_uploaded_file($tmp)) {
      error_log("UPLOAD: file #{$i} '{$name}' tmp invalid tmp='{$tmp}'");
      $result['errors'][] = "Файл '{$name}' не прошёл проверку загрузки (tmp).";
      continue;
    }

    $safeBase = preg_replace('~[^a-z0-9_\-]+~i', '_', pathinfo($name, PATHINFO_FILENAME));
    $fileName = date('Ymd_His') . "_{$newsId}_" . $safeBase . "_" . bin2hex(random_bytes(4)) . "." . $ext;

    $dest = rtrim($uploadDir, '/\\') . DIRECTORY_SEPARATOR . $fileName;
    if (!move_uploaded_file($tmp, $dest)) {
      error_log("UPLOAD: move_uploaded_file failed for '{$name}' to '{$dest}'");
      $result['errors'][] = "Не удалось сохранить файл '{$name}' (ошибка записи).";
      continue;
    }

    $filePath = rtrim($uploadUrl, '/') . '/' . $fileName;

    if ($hasNewsMedia && isset($mediaCols['news_id'])) {
      $type = guess_type_by_ext($ext);

      $fields = ['news_id'];
      $vals = [$newsId];
      $qs = ['?'];

      if (isset($mediaCols['type']))      { $fields[]='type';      $vals[]=$type;     $qs[]='?'; }
      if (isset($mediaCols['file_path'])) { $fields[]='file_path'; $vals[]=$filePath; $qs[]='?'; }
      if (isset($mediaCols['mime_type'])) { $fields[]='mime_type'; $vals[]=$mime;     $qs[]='?'; }
      if (isset($mediaCols['sort_order'])){ $fields[]='sort_order';$vals[]=(++$nextSort); $qs[]='?'; }

      $sql = "INSERT INTO news_media (" . implode(',', $fields) . ") VALUES (" . implode(',', $qs) . ")";
      try {
        $pdo->prepare($sql)->execute($vals);
      } catch (Throwable $e) {
        error_log("UPLOAD: DB insert failed: " . $e->getMessage());
        if (is_file($dest)) @unlink($dest);
        $result['errors'][] = "Файл '{$name}' сохранился, но не привязался в БД (news_media).";
        continue;
      }
    }

    $result['saved']++;
  }

  if ($result['received'] > 0 && $result['saved'] === 0 && empty($result['errors'])) {
    $result['errors'][] = "Файлы не сохранились. Проверьте лимиты: upload_max_filesize=" .
      (string)ini_get('upload_max_filesize') . ", post_max_size=" . (string)ini_get('post_max_size') .
      ", max_file_uploads=" . (string)ini_get('max_file_uploads') . ".";
  }

  return $result;
}


function normalize_lines(string $input): array {
  $input = str_replace("\r\n", "\n", $input);
  $input = str_replace("\r", "\n", $input);
  $lines = array_map('trim', explode("\n", $input));
  $out = [];
  foreach ($lines as $line) {
    if ($line === '') continue;
    $line = trim($line, " \t\n\r\0\x0B,");
    if ($line === '') continue;
    $out[] = $line;
  }
  return $out;
}

function is_youtube_url(string $url): bool {
  $u = strtolower($url);
  return (str_contains($u, 'youtube.com') || str_contains($u, 'youtu.be'));
}

function youtube_embed_url(string $url): string {
  if (preg_match('~youtu\.be/([a-zA-Z0-9_-]{6,})~', $url, $m)) {
    return "https://www.youtube.com/embed/" . $m[1];
  }
  if (preg_match('~[?&]v=([a-zA-Z0-9_-]{6,})~', $url, $m)) {
    return "https://www.youtube.com/embed/" . $m[1];
  }
  if (preg_match('~youtube\.com/shorts/([a-zA-Z0-9_-]{6,})~', $url, $m)) {
    return "https://www.youtube.com/embed/" . $m[1];
  }
  return '';
}

function detect_media_type_from_url(string $url): string {
  if (is_youtube_url($url)) return 'youtube';

  $path = parse_url($url, PHP_URL_PATH);
  $ext = is_string($path) ? strtolower(pathinfo($path, PATHINFO_EXTENSION)) : '';

  if (in_array($ext, ['mp4','mov','webm'], true)) return 'video';

  return 'file';
}

function save_external_media_urls(PDO $pdo, int $newsId, string $raw, bool $hasNewsMedia, array $mediaCols): array {
  $result = ['saved' => 0, 'errors' => []];

  if (!$hasNewsMedia || !isset($mediaCols['news_id']) || !isset($mediaCols['file_path']) || !isset($mediaCols['type'])) {
    return $result; 
  }

  $urls = normalize_lines($raw);
  if (!$urls) return $result;

  $nextSort = 0;
  if (isset($mediaCols['sort_order'])) {
    try {
      $st = $pdo->prepare("SELECT COALESCE(MAX(sort_order),0) AS m FROM news_media WHERE news_id=?");
      $st->execute([$newsId]);
      $row = $st->fetch();
      $nextSort = (int)($row['m'] ?? 0);
    } catch (Throwable $e) {
      $nextSort = 0;
    }
  }

  foreach ($urls as $url) {
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
      $result['errors'][] = "Некорректный URL: {$url}";
      continue;
    }
    if (!preg_match('~^https?://~i', $url)) {
      $result['errors'][] = "Разрешены только http/https: {$url}";
      continue;
    }

    if (strlen($url) > 255) {
      $result['errors'][] = "Ссылка длиннее 255 символов и не сохранена: " . substr($url, 0, 80) . "…";
      continue;
    }

    $type = detect_media_type_from_url($url);

    $fields = ['news_id','type','file_path'];
    $vals = [$newsId, $type, $url];
    $qs = ['?','?','?'];

    if (isset($mediaCols['mime_type'])) {
      $fields[] = 'mime_type';
      $vals[] = 'text/url';
      $qs[] = '?';
    }
    if (isset($mediaCols['sort_order'])) {
      $fields[] = 'sort_order';
      $vals[] = (++$nextSort);
      $qs[] = '?';
    }

    $sql = "INSERT INTO news_media (" . implode(',', $fields) . ") VALUES (" . implode(',', $qs) . ")";
    try {
      $pdo->prepare($sql)->execute($vals);
      $result['saved']++;
    } catch (Throwable $e) {
      error_log("URL_MEDIA: insert failed: " . $e->getMessage());
      $result['errors'][] = "Не удалось сохранить ссылку: {$url}";
    }
  }

  return $result;
}

$DB_HOST = require_env('DB_HOST');
$DB_PORT = env_int('DB_PORT', 3306);
$DB_NAME = require_env('DB_NAME');
$DB_USER = require_env('DB_USER');
$DB_PASS = require_env('DB_PASS');

$ADMIN_USER   = require_env('ADMIN_USER');
$ADMIN_PASS   = require_env('ADMIN_PASS');
$ADMIN_SECRET = require_env('ADMIN_SECRET');
$TTL          = env_int('ADMIN_SESSION_TTL', 1200);

$UPLOAD_DIR = require_env('UPLOAD_DIR');
$UPLOAD_URL = require_env('UPLOAD_URL');

if (is_probably_url($UPLOAD_DIR)) {
  http_response_code(500);
  echo "Server misconfigured: UPLOAD_DIR must be a local filesystem path, not URL. Given: " . e($UPLOAD_DIR);
  exit;
}

if (!is_dir($UPLOAD_DIR)) { @mkdir($UPLOAD_DIR, 0755, true); }

$action = (string)($_GET['a'] ?? '');
$pdo = db();

$newsCols = columns($pdo, 'news');
$hasNewsMedia = table_exists($pdo, 'news_media');
$mediaCols = $hasNewsMedia ? columns($pdo, 'news_media') : [];

$authOk = is_admin_authed($ADMIN_USER, $ADMIN_SECRET);

if ($action === 'logout') {
  clear_admin_cookie();
  header('Location: /admin.php');
  exit;
}

$loginError = '';
if (!$authOk && $_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'login') {
  csrf_check();
  $u = trim((string)($_POST['user'] ?? ''));
  $p = (string)($_POST['pass'] ?? '');

  if ($u === $ADMIN_USER && hash_equals($ADMIN_PASS, $p)) {
    set_admin_cookie($ADMIN_USER, $TTL, $ADMIN_SECRET);
    set_csrf_cookie();
    header('Location: /admin.php');
    exit;
  } else {
    $loginError = 'Неверный логин или пароль';
  }
}

if (!$authOk) {
  if (read_csrf_token() === '') set_csrf_cookie();
  ?>
  <!doctype html>
  <html lang="ru">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Вход — Админка</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
      body{background:#f6f6f6;}
      .login-wrap{min-height:100vh; display:flex; align-items:center;}
      .card{border:1px solid rgba(0,0,0,.08); border-radius:16px;}
      .btn{border-radius:12px;}
      .form-control{border-radius:12px;}
    </style>
  </head>
  <body>
    <div class="container login-wrap">
      <div class="row justify-content-center w-100">
        <div class="col-12 col-sm-10 col-md-7 col-lg-5 col-xl-4">
          <div class="card shadow-sm">
            <div class="card-body p-4 p-md-5">
              <div class="d-flex align-items-center gap-3 mb-3">
                <div class="rounded-4 bg-dark" style="width:40px;height:40px;"></div>
                <div>
                  <div class="h5 mb-0">Админ-панель</div>
                  <div class="text-muted small">Сессия: <?= (int)($TTL/60) ?> минут</div>
                </div>
              </div>

              <?php if ($loginError): ?>
                <div class="alert alert-danger"><?= e($loginError) ?></div>
              <?php endif; ?>

              <form method="post" action="/admin.php?a=login">
                <?= csrf_field() ?>
                <div class="mb-3">
                  <label class="form-label">Логин</label>
                  <input class="form-control form-control-lg" name="user" autocomplete="username" required>
                </div>
                <div class="mb-3">
                  <label class="form-label">Пароль</label>
                  <input class="form-control form-control-lg" name="pass" type="password" autocomplete="current-password" required>
                </div>
                <button class="btn btn-dark btn-lg w-100" type="submit">Войти</button>
              </form>

              <div class="text-muted small mt-3">
                Рекомендуется HTTPS + длинный ADMIN_SECRET.
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </body>
  </html>
  <?php
  exit;
}

set_admin_cookie($ADMIN_USER, $TTL, $ADMIN_SECRET);
if (read_csrf_token() === '') set_csrf_cookie();

function redirect_home(bool $ok = false): void {
  header('Location: /admin.php' . ($ok ? '?ok=1' : ''));
  exit;
}

if ($action === 'create' && $_SERVER['REQUEST_METHOD'] === 'POST') {
  csrf_check();

  $title_ru = trim((string)($_POST['title_ru'] ?? ''));
  $title_kk = trim((string)($_POST['title_kk'] ?? ''));
  $title_en = trim((string)($_POST['title_en'] ?? ''));
  $body_ru  = trim((string)($_POST['body_ru'] ?? ''));
  $body_kk  = trim((string)($_POST['body_kk'] ?? ''));
  $body_en  = trim((string)($_POST['body_en'] ?? ''));
  $is_published = (int)($_POST['is_published'] ?? 0);

  $published_at = from_datetime_local((string)($_POST['published_at_local'] ?? ''));
  if ($is_published === 1 && $published_at === null && isset($newsCols['published_at'])) {
    $published_at = date('Y-m-d H:i:s');
  }

  $fields = [];
  $vals = [];
  $qs = [];

  $map = [
    'title_ru'=>$title_ru, 'title_kk'=>$title_kk, 'title_en'=>$title_en,
    'body_ru'=>$body_ru,   'body_kk'=>$body_kk,   'body_en'=>$body_en,
    'is_published'=>$is_published,
    'published_at'=>$published_at,
  ];

  foreach ($map as $col => $val) {
    if (isset($newsCols[$col])) { $fields[] = $col; $vals[] = $val; $qs[] = '?'; }
  }
  if (isset($newsCols['created_at'])) { $fields[]='created_at'; $vals[] = date('Y-m-d H:i:s'); $qs[]='?'; }

  if (!$fields) redirect_home();

  $sql = "INSERT INTO news (" . implode(',', $fields) . ") VALUES (" . implode(',', $qs) . ")";
  $pdo->prepare($sql)->execute($vals);
  $newsId = (int)$pdo->lastInsertId();

  $u = save_uploaded_media($pdo, $newsId, $UPLOAD_DIR, $UPLOAD_URL, $hasNewsMedia, $mediaCols);
  if ($u['received'] > 0) {
    if ($u['saved'] === 0) {
      flash_set('warn', "Файлы не прикрепились. Причины: " . implode(' | ', $u['errors']));
    } else if (!empty($u['errors'])) {
      flash_set('warn', "Часть файлов не прикрепилась: " . implode(' | ', $u['errors']));
    } else {
      flash_set('info', "Прикреплено файлов: {$u['saved']} из {$u['received']}");
    }
  }

  $urlsRaw = (string)($_POST['video_urls'] ?? '');
  $ur = save_external_media_urls($pdo, $newsId, $urlsRaw, $hasNewsMedia, $mediaCols);
  if ($ur['saved'] > 0 && empty($ur['errors'])) {
    flash_set('info', "Ссылок сохранено: {$ur['saved']}" . ($u['saved'] ? " (+ файлы: {$u['saved']})" : ""));
  } elseif ($ur['saved'] > 0 && !empty($ur['errors'])) {
    flash_set('warn', "Часть ссылок сохранена ({$ur['saved']}), но есть ошибки: " . implode(' | ', $ur['errors']));
  } elseif ($ur['saved'] === 0 && !empty($ur['errors'])) {
    flash_set('warn', "Ссылки не сохранены: " . implode(' | ', $ur['errors']));
  }

  header("Location: /admin.php?edit={$newsId}&ok=1");
  exit;
}

if ($action === 'save' && $_SERVER['REQUEST_METHOD'] === 'POST') {
  csrf_check();

  $id = (int)($_POST['id'] ?? 0);
  if ($id <= 0) redirect_home();

  $title_ru = trim((string)($_POST['title_ru'] ?? ''));
  $title_kk = trim((string)($_POST['title_kk'] ?? ''));
  $title_en = trim((string)($_POST['title_en'] ?? ''));
  $body_ru  = trim((string)($_POST['body_ru'] ?? ''));
  $body_kk  = trim((string)($_POST['body_kk'] ?? ''));
  $body_en  = trim((string)($_POST['body_en'] ?? ''));
  $is_published = (int)($_POST['is_published'] ?? 0);

  $published_at = from_datetime_local((string)($_POST['published_at_local'] ?? ''));
  if ($is_published === 1 && $published_at === null && isset($newsCols['published_at'])) {
    $published_at = date('Y-m-d H:i:s');
  }

  $set = [];
  $vals = [];

  $map = [
    'title_ru'=>$title_ru, 'title_kk'=>$title_kk, 'title_en'=>$title_en,
    'body_ru'=>$body_ru,   'body_kk'=>$body_kk,   'body_en'=>$body_en,
    'is_published'=>$is_published,
    'published_at'=>$published_at,
  ];
  foreach ($map as $col => $val) {
    if (isset($newsCols[$col])) { $set[] = "`$col` = ?"; $vals[] = $val; }
  }

  if ($set) {
    $vals[] = $id;
    $pdo->prepare("UPDATE news SET " . implode(',', $set) . " WHERE id = ?")->execute($vals);
  }

  $u = save_uploaded_media($pdo, $id, $UPLOAD_DIR, $UPLOAD_URL, $hasNewsMedia, $mediaCols);
  if ($u['received'] > 0) {
    if ($u['saved'] === 0) {
      flash_set('warn', "Файлы не прикрепились. Причины: " . implode(' | ', $u['errors']));
    } else if (!empty($u['errors'])) {
      flash_set('warn', "Часть файлов не прикрепилась: " . implode(' | ', $u['errors']));
    } else {
      flash_set('info', "Прикреплено файлов: {$u['saved']} из {$u['received']}");
    }
  }

  $urlsRaw = (string)($_POST['video_urls'] ?? '');
  $ur = save_external_media_urls($pdo, $id, $urlsRaw, $hasNewsMedia, $mediaCols);
  if ($ur['saved'] > 0 && empty($ur['errors'])) {
    flash_set('info', "Ссылок сохранено: {$ur['saved']}" . ($u['saved'] ? " (+ файлы: {$u['saved']})" : ""));
  } elseif ($ur['saved'] > 0 && !empty($ur['errors'])) {
    flash_set('warn', "Часть ссылок сохранена ({$ur['saved']}), но есть ошибки: " . implode(' | ', $ur['errors']));
  } elseif ($ur['saved'] === 0 && !empty($ur['errors'])) {
    flash_set('warn', "Ссылки не сохранены: " . implode(' | ', $ur['errors']));
  }

  header("Location: /admin.php?edit={$id}&ok=1");
  exit;
}

if ($action === 'delete' && $_SERVER['REQUEST_METHOD'] === 'POST') {
  csrf_check();

  $id = (int)($_POST['id'] ?? 0);
  if ($id <= 0) redirect_home();

  if ($hasNewsMedia && isset($mediaCols['news_id']) && isset($mediaCols['file_path'])) {
    try {
      $st = $pdo->prepare("SELECT file_path FROM news_media WHERE news_id=?");
      $st->execute([$id]);
      foreach ($st->fetchAll() as $r) {
        delete_media_file((string)($r['file_path'] ?? ''), $UPLOAD_URL, $UPLOAD_DIR);
      }
    } catch (Throwable $e) {}
    try { $pdo->prepare("DELETE FROM news_media WHERE news_id=?")->execute([$id]); } catch (Throwable $e) {}
  }

  $pdo->prepare("DELETE FROM news WHERE id=?")->execute([$id]);
  redirect_home(true);
}

if ($action === 'delmedia' && $_SERVER['REQUEST_METHOD'] === 'POST') {
  csrf_check();

  $mid = (int)($_POST['mid'] ?? 0);
  $nid = (int)($_POST['nid'] ?? 0);
  if (!$hasNewsMedia || $mid <= 0 || $nid <= 0) redirect_home();

  if (isset($mediaCols['file_path'])) {
    $st = $pdo->prepare("SELECT file_path FROM news_media WHERE id=?");
    $st->execute([$mid]);
    $m = $st->fetch();
    if ($m) delete_media_file((string)($m['file_path'] ?? ''), $UPLOAD_URL, $UPLOAD_DIR);
  }
  $pdo->prepare("DELETE FROM news_media WHERE id=?")->execute([$mid]);

  header("Location: /admin.php?edit={$nid}&ok=1");
  exit;
}

$editId = (int)($_GET['edit'] ?? 0);
$ok = (int)($_GET['ok'] ?? 0);
$q = trim((string)($_GET['q'] ?? ''));

$params = [];
$sqlList = "SELECT * FROM news";
if ($q !== '') {
  $whereParts = [];
  if (isset($newsCols['title_ru'])) { $whereParts[] = "title_ru LIKE :q"; }
  if (isset($newsCols['title_kk'])) { $whereParts[] = "title_kk LIKE :q"; }
  if (isset($newsCols['title_en'])) { $whereParts[] = "title_en LIKE :q"; }
  if ($whereParts) {
    $sqlList .= " WHERE (" . implode(" OR ", $whereParts) . ")";
    $params[':q'] = "%{$q}%";
  }
}
$sqlList .= " ORDER BY " . (isset($newsCols['published_at']) ? "COALESCE(`published_at`,`created_at`)" : "id") . " DESC, id DESC LIMIT 200";
$stmt = $pdo->prepare($sqlList);
$stmt->execute($params);
$newsList = $stmt->fetchAll();

$editing = null;
$mediaList = [];
if ($editId > 0) {
  $st = $pdo->prepare("SELECT * FROM news WHERE id=?");
  $st->execute([$editId]);
  $editing = $st->fetch() ?: null;

  if ($editing && $hasNewsMedia && isset($mediaCols['news_id'])) {
    try {
      $order = isset($mediaCols['sort_order']) ? "sort_order ASC, id ASC" : "id ASC";
      $st2 = $pdo->prepare("SELECT * FROM news_media WHERE news_id=? ORDER BY {$order}");
      $st2->execute([$editId]);
      $mediaList = $st2->fetchAll();
    } catch (Throwable $e) { $mediaList = []; }
  }
}

function status_badge(array $news, array $newsCols): string {
  $pub = isset($newsCols['is_published']) ? (int)($news['is_published'] ?? 0) : 0;
  if ($pub === 1) return '<span class="badge text-bg-dark">Опубликовано</span>';
  return '<span class="badge text-bg-secondary">Черновик</span>';
}

$flashWarn = flash_get('warn');
$flashInfo = flash_get('info');

$iniUpload = (string)ini_get('upload_max_filesize');
$iniPost   = (string)ini_get('post_max_size');
$iniMaxFiles = (string)ini_get('max_file_uploads');

?>
<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Админ-панель — Новости</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body{ background:#f7f7f8; color:#111; }
    .appbar{
      position: sticky; top:0; z-index: 20;
      background:#fff; border-bottom:1px solid rgba(0,0,0,.08);
    }
    .card{
      border:1px solid rgba(0,0,0,.08);
      border-radius:16px;
      box-shadow: 0 6px 18px rgba(0,0,0,.04);
    }
    .btn, .form-control, .form-select{ border-radius:12px; }
    .form-control, .form-select{ border-color: rgba(0,0,0,.15); }
    .form-control:focus, .form-select:focus{
      border-color: rgba(0,0,0,.45);
      box-shadow: 0 0 0 .25rem rgba(0,0,0,.08);
    }
    .table thead th{ color:#444; font-weight:700; }
    .table td, .table th{ border-top-color: rgba(0,0,0,.06); }
    .table-hover tbody tr:hover{ background: rgba(0,0,0,.03); }
    .muted{ color:#6b7280; }
    .thumb img, .thumb video{ width:100%; border-radius:14px; display:block; }
    .split-actions{ gap:.5rem; }
    @media (max-width: 576px){
      .container-fluid{ padding-left:12px; padding-right:12px; }
    }
    code.kv{background:#f2f2f2; padding:.2rem .35rem; border-radius:8px;}
  </style>
</head>

<body>
  <div class="appbar">
    <div class="container-fluid py-3">
      <div class="d-flex align-items-center justify-content-between flex-wrap gap-3">
        <div class="d-flex align-items-center gap-3">
          <div class="rounded-4 bg-dark" style="width:40px;height:40px;"></div>
          <div>
            <div class="h5 mb-0">Админ-панель новостей</div>
            <div class="muted small">Управление публикациями и медиа</div>
          </div>
        </div>

        <div class="d-flex align-items-center gap-2">
          <span class="badge text-bg-light border">TTL: <?= (int)($TTL/60) ?> мин</span>
          <a class="btn btn-outline-dark" href="/admin.php">Главная</a>
          <a class="btn btn-dark" href="/admin.php?a=logout">Выйти</a>
        </div>
      </div>
    </div>
  </div>

  <div class="container-fluid py-3">
    <?php if ($ok): ?>
      <div class="alert alert-success">Готово</div>
    <?php endif; ?>

    <?php if ($flashInfo): ?>
      <div class="alert alert-info"><?= e($flashInfo) ?></div>
    <?php endif; ?>

    <?php if ($flashWarn): ?>
      <div class="alert alert-warning">
        <div class="fw-semibold mb-1">Внимание</div>
        <div><?= e($flashWarn) ?></div>
        <div class="mt-2 muted small">
          Подсказка: возможно только были прикреплены файлы или ссылки.
        </div>
      </div>
    <?php endif; ?>

    <div class="row g-3">
      <div class="col-12 col-lg-5 col-xxl-4">
        <div class="card">
          <div class="card-body">
            <div class="d-flex align-items-end justify-content-between flex-wrap gap-2">
              <div>
                <div class="h6 mb-0">Новости</div>
              </div>

              <form class="d-flex gap-2" method="get" action="/admin.php">
                <input class="form-control form-control-sm" name="q" value="<?= e($q) ?>" placeholder="Поиск по заголовкам…">
                <button class="btn btn-dark btn-sm" type="submit">Найти</button>
              </form>
            </div>

            <div class="table-responsive mt-3">
              <table class="table table-hover align-middle mb-0">
                <thead>
                  <tr>
                    <th style="width:86px;">ID</th>
                    <th>Заголовок (RU)</th>
                    <th style="width:140px;">Статус</th>
                    <th style="width:120px;"></th>
                  </tr>
                </thead>
                <tbody>
                  <?php foreach ($newsList as $n): ?>
                    <tr>
                      <td class="muted">#<?= (int)$n['id'] ?></td>
                      <td><?= e(val($n,'title_ru')) ?: '<span class="muted">Без заголовка</span>' ?></td>
                      <td><?= status_badge($n, $newsCols) ?></td>
                      <td>
                        <a class="btn btn-outline-dark btn-sm w-100" href="/admin.php?edit=<?= (int)$n['id'] ?>">Открыть</a>
                      </td>
                    </tr>
                  <?php endforeach; ?>
                </tbody>
              </table>
            </div>

          </div>
        </div>
      </div>

      <div class="col-12 col-lg-7 col-xxl-8">
        <div class="card">
          <div class="card-body">
            <div class="d-flex align-items-end justify-content-between flex-wrap gap-2">
              <div>
                <div class="h6 mb-0"><?= $editing ? ('Редактирование новости #' . (int)$editing['id']) : 'Создать новость' ?></div>
              </div>

              <?php if ($editing): ?>
                <div class="d-flex gap-2 align-items-center flex-wrap">
                  <?= status_badge($editing, $newsCols) ?>
                  <?php if (isset($newsCols['published_at'])): ?>
                    <span class="badge text-bg-light border">
                      Дата: <?= e((string)($editing['published_at'] ?? '—')) ?>
                    </span>
                  <?php endif; ?>
                </div>
              <?php endif; ?>
            </div>

            <hr class="my-3">

            <?php if ($editing): ?>
              <form method="post" action="/admin.php?a=save" enctype="multipart/form-data">
                <?= csrf_field() ?>
                <input type="hidden" name="id" value="<?= (int)$editing['id'] ?>">

                <div class="row g-3">
                  <?php if (isset($newsCols['title_ru'])): ?>
                    <div class="col-12 col-md-4">
                      <label class="form-label">Заголовок (RU)</label>
                      <input class="form-control" name="title_ru" value="<?= e(val($editing,'title_ru')) ?>">
                    </div>
                  <?php endif; ?>
                  <?php if (isset($newsCols['title_kk'])): ?>
                    <div class="col-12 col-md-4">
                      <label class="form-label">Заголовок (KK)</label>
                      <input class="form-control" name="title_kk" value="<?= e(val($editing,'title_kk')) ?>">
                    </div>
                  <?php endif; ?>
                  <?php if (isset($newsCols['title_en'])): ?>
                    <div class="col-12 col-md-4">
                      <label class="form-label">Заголовок (EN)</label>
                      <input class="form-control" name="title_en" value="<?= e(val($editing,'title_en')) ?>">
                    </div>
                  <?php endif; ?>

                  <?php if (isset($newsCols['body_ru'])): ?>
                    <div class="col-12 col-md-4">
                      <label class="form-label">Текст (RU)</label>
                      <textarea class="form-control" rows="7" name="body_ru"><?= e(val($editing,'body_ru')) ?></textarea>
                    </div>
                  <?php endif; ?>
                  <?php if (isset($newsCols['body_kk'])): ?>
                    <div class="col-12 col-md-4">
                      <label class="form-label">Текст (KK)</label>
                      <textarea class="form-control" rows="7" name="body_kk"><?= e(val($editing,'body_kk')) ?></textarea>
                    </div>
                  <?php endif; ?>
                  <?php if (isset($newsCols['body_en'])): ?>
                    <div class="col-12 col-md-4">
                      <label class="form-label">Текст (EN)</label>
                      <textarea class="form-control" rows="7" name="body_en"><?= e(val($editing,'body_en')) ?></textarea>
                    </div>
                  <?php endif; ?>

                  <?php if (isset($newsCols['is_published'])): ?>
                    <div class="col-12 col-md-4">
                      <label class="form-label">Статус</label>
                      <select class="form-select" name="is_published">
                        <option value="0" <?= ((int)($editing['is_published'] ?? 0)===0?'selected':'') ?>>Черновик</option>
                        <option value="1" <?= ((int)($editing['is_published'] ?? 0)===1?'selected':'') ?>>Опубликовано</option>
                      </select>
                      <div class="form-text muted">Если “Опубликовано” — дата может выставиться автоматически.</div>
                    </div>
                  <?php endif; ?>

                  <?php if (isset($newsCols['published_at'])): ?>
                    <div class="col-12 col-md-4">
                      <label class="form-label">Дата публикации</label>
                      <input class="form-control" type="datetime-local" name="published_at_local" value="<?= e(to_datetime_local((string)($editing['published_at'] ?? ''))) ?>">
                      <div class="form-text muted">Выберите дату и время публикации</div>
                    </div>
                  <?php endif; ?>

                  <div class="col-12 col-md-4">
                    <label class="form-label">Добавить медиа (файлы)</label>
                    <input class="form-control" type="file" name="media[]" multiple accept="image/*,video/*,.pdf">
                    <div class="form-text muted">Поддержка: jpg/png/webp/gif/heic, mp4/mov, pdf. До 25MB каждый.</div>
                  </div>

                  <div class="col-12">
                    <label class="form-label">Ссылки на видео/медиа (по одной на строку)</label>
                    <textarea class="form-control" rows="4" name="video_urls"
                      placeholder="https://youtube.com/watch?v=...&#10;https://youtu.be/...&#10;https://site.com/video.mp4&#10;https://tiktok.com/..."></textarea>
                    <div class="form-text muted">
                      Ограничение: каждая ссылка ≤ 255 символов.
                    </div>
                  </div>
                </div>

                <div class="d-flex flex-wrap mt-4 split-actions">
                  <button class="btn btn-dark" type="submit">Сохранить</button>

                  <button
                    class="btn btn-outline-danger"
                    type="submit"
                    formaction="/admin.php?a=delete"
                    formmethod="post"
                    onclick="return confirm('Удалить новость и файлы?')"
                  >
                    Удалить
                  </button>

                  <a class="btn btn-outline-dark ms-auto" href="/api/news.php?id=<?= (int)$editing['id'] ?>&lang=ru" target="_blank">
                    Открыть через API (RU)
                  </a>
                </div>
              </form>

              <?php if ($hasNewsMedia): ?>
                <hr class="my-4">
                <div class="d-flex align-items-center justify-content-between flex-wrap gap-2">
                  <div class="h6 mb-0">Медиафайлы</div>
                  <div class="muted small">Связанные с этой новостью</div>
                </div>

                <?php if (!$mediaList): ?>
                  <div class="muted mt-3">Файлов пока нет.</div>
                <?php else: ?>
                  <div class="row g-3 mt-1">
                    <?php foreach ($mediaList as $m): ?>
                      <?php
                        $fp = (string)($m['file_path'] ?? '');
                        $mime = (string)($m['mime_type'] ?? '');
                        $type = (string)($m['type'] ?? '');
                        $isUrl = is_probably_url($fp);

                        $isImg = ($type === 'image') || ($mime && str_starts_with($mime,'image/'));
                        $isVid = ($type === 'video') || ($mime && str_starts_with($mime,'video/'));
                        $isYt  = ($type === 'youtube');

                        $ytEmbed = $isYt ? youtube_embed_url($fp) : '';
                        $path = $isUrl ? (string)parse_url($fp, PHP_URL_PATH) : '';
                        $ext = $path ? strtolower(pathinfo($path, PATHINFO_EXTENSION)) : '';
                        $isDirectVideoUrl = $isUrl && in_array($ext, ['mp4','mov','webm'], true);
                      ?>
                      <div class="col-12 col-sm-6 col-md-4 col-xxl-3">
                        <div class="card">
                          <div class="card-body">
                            <div class="muted small">ID файла: #<?= (int)$m['id'] ?></div>
                            <?php if (isset($m['sort_order'])): ?>
                              <div class="muted small">sort_order: <?= (int)$m['sort_order'] ?></div>
                            <?php endif; ?>
                            <div class="muted small">type: <?= e($type) ?></div>

                            <div class="thumb mt-2">
                              <?php if ($isImg && !$isUrl): ?>
                                <img src="<?= e($fp) ?>" alt="">
                              <?php elseif ($isVid && !$isUrl): ?>
                                <video src="<?= e($fp) ?>" controls></video>
                              <?php elseif ($isYt && $ytEmbed !== ''): ?>
                                <div class="ratio ratio-16x9">
                                  <iframe src="<?= e($ytEmbed) ?>" allowfullscreen></iframe>
                                </div>
                              <?php elseif ($isDirectVideoUrl): ?>
                                <video src="<?= e($fp) ?>" controls></video>
                              <?php else: ?>
                                <a class="btn btn-outline-dark w-100" href="<?= e($fp) ?>" target="_blank">Открыть ссылку</a>
                              <?php endif; ?>
                            </div>

                            <div class="d-flex gap-2 mt-3">
                              <a class="btn btn-outline-dark btn-sm w-100" href="<?= e($fp) ?>" target="_blank">Просмотр</a>

                              <form method="post" action="/admin.php?a=delmedia" class="w-100" onsubmit="return confirm('Удалить этот файл/ссылку?')">
                                <?= csrf_field() ?>
                                <input type="hidden" name="mid" value="<?= (int)$m['id'] ?>">
                                <input type="hidden" name="nid" value="<?= (int)$editing['id'] ?>">
                                <button class="btn btn-outline-danger btn-sm w-100" type="submit">Удалить</button>
                              </form>
                            </div>

                          </div>
                        </div>
                      </div>
                    <?php endforeach; ?>
                  </div>
                <?php endif; ?>
              <?php endif; ?>

            <?php else: ?>
              <form method="post" action="/admin.php?a=create" enctype="multipart/form-data">
                <?= csrf_field() ?>

                <div class="row g-3">
                  <?php if (isset($newsCols['title_ru'])): ?>
                    <div class="col-12 col-md-4">
                      <label class="form-label">Заголовок (RU)</label>
                      <input class="form-control" name="title_ru">
                    </div>
                  <?php endif; ?>
                  <?php if (isset($newsCols['title_kk'])): ?>
                    <div class="col-12 col-md-4">
                      <label class="form-label">Заголовок (KK)</label>
                      <input class="form-control" name="title_kk">
                    </div>
                  <?php endif; ?>
                  <?php if (isset($newsCols['title_en'])): ?>
                    <div class="col-12 col-md-4">
                      <label class="form-label">Заголовок (EN)</label>
                      <input class="form-control" name="title_en">
                    </div>
                  <?php endif; ?>

                  <?php if (isset($newsCols['body_ru'])): ?>
                    <div class="col-12 col-md-4">
                      <label class="form-label">Текст (RU)</label>
                      <textarea class="form-control" rows="7" name="body_ru"></textarea>
                    </div>
                  <?php endif; ?>
                  <?php if (isset($newsCols['body_kk'])): ?>
                    <div class="col-12 col-md-4">
                      <label class="form-label">Текст (KK)</label>
                      <textarea class="form-control" rows="7" name="body_kk"></textarea>
                    </div>
                  <?php endif; ?>
                  <?php if (isset($newsCols['body_en'])): ?>
                    <div class="col-12 col-md-4">
                      <label class="form-label">Текст (EN)</label>
                      <textarea class="form-control" rows="7" name="body_en"></textarea>
                    </div>
                  <?php endif; ?>

                  <?php if (isset($newsCols['is_published'])): ?>
                    <div class="col-12 col-md-4">
                      <label class="form-label">Статус</label>
                      <select class="form-select" name="is_published">
                        <option value="0">Черновик</option>
                        <option value="1">Опубликовано</option>
                      </select>
                    </div>
                  <?php endif; ?>

                  <?php if (isset($newsCols['published_at'])): ?>
                    <div class="col-12 col-md-4">
                      <label class="form-label">Дата публикации</label>
                      <input class="form-control" type="datetime-local" name="published_at_local">
                      <div class="form-text muted">Выберите дату и время публикации</div>
                    </div>
                  <?php endif; ?>

                  <div class="col-12 col-md-4">
                    <label class="form-label">Медиафайлы (загрузка)</label>
                    <input class="form-control" type="file" name="media[]" multiple accept="image/*,video/*,.pdf">
                    <div class="form-text muted">Поддержка: jpg/png/webp/gif/heic, mp4/mov, pdf. До 25MB каждый.</div>
                  </div>

                  <div class="col-12">
                    <label class="form-label">Ссылки на видео/медиа (по одной на строку)</label>
                    <textarea class="form-control" rows="4" name="video_urls"
                      placeholder="https://youtube.com/watch?v=...&#10;https://youtu.be/...&#10;https://site.com/video.mp4&#10;https://tiktok.com/..."></textarea>
                    <div class="form-text muted">
                      Ограничение: каждая ссылка ≤ 255 символов.
                    </div>
                  </div>
                </div>

                <div class="d-flex gap-2 flex-wrap mt-4">
                  <button class="btn btn-dark" type="submit">Создать</button>
                </div>
              </form>
            <?php endif; ?>

          </div>
        </div>
      </div>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
