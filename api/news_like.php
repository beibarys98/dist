<?php
declare(strict_types=1);

require_once __DIR__ . '/db.php';

try {
  $pdo = db();
  $id = get_int('id', 0);
  if ($id <= 0) json_error("Missing id", 400, 'bad_request');

  $delta = isset($_GET['delta']) ? (int)$_GET['delta'] : 1;
  if (!in_array($delta, [-1, 1], true)) $delta = 1;

  $cols = [];
  $st = $pdo->query("SHOW COLUMNS FROM news");
  foreach ($st->fetchAll() as $r) $cols[$r['Field']] = true;

  $likesField = null;
  foreach (['likes', 'like_count', 'likes_count'] as $c) {
    if (isset($cols[$c])) { $likesField = $c; break; }
  }

  if (!$likesField) {
    echo json_encode(['likes' => 0], JSON_UNESCAPED_UNICODE);
    exit;
  }

  if ($delta === 1) {
    $sqlUp = "UPDATE news SET `$likesField` = COALESCE(`$likesField`,0) + 1 WHERE id = ?";
  } else {
    $sqlUp = "UPDATE news SET `$likesField` = GREATEST(COALESCE(`$likesField`,0) - 1, 0) WHERE id = ?";
  }
  $pdo->prepare($sqlUp)->execute([$id]);

  $sqlSel = "SELECT `$likesField` AS likes FROM news WHERE id = ?";
  $stmt = $pdo->prepare($sqlSel);
  $stmt->execute([$id]);
  $row = $stmt->fetch();

  if (!$row) {
    json_error("News not found", 404, 'not_found');
  }

  echo json_encode(['likes' => (int)($row['likes'] ?? 0)], JSON_UNESCAPED_UNICODE);

} catch (Throwable $e) {
  json_error($e->getMessage(), 500, 'server_error');
}
