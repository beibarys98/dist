<?php
declare(strict_types=1);

require_once __DIR__ . '/db.php';

try {
  $pdo = db();
  $id = get_int('id', 0);
  if ($id <= 0) json_error("Missing id", 400, 'bad_request');

  $cols = [];
  $st = $pdo->query("SHOW COLUMNS FROM news");
  foreach ($st->fetchAll() as $r) $cols[$r['Field']] = true;

  $viewsField = null;
  foreach (['views', 'view_count', 'views_count'] as $c) {
    if (isset($cols[$c])) { $viewsField = $c; break; }
  }

  if (!$viewsField) {
    echo json_encode(['views' => 0], JSON_UNESCAPED_UNICODE);
    exit;
  }

  $sqlUp = "UPDATE news SET `$viewsField` = COALESCE(`$viewsField`,0) + 1 WHERE id = ?";
  $pdo->prepare($sqlUp)->execute([$id]);

  $sqlSel = "SELECT `$viewsField` AS views FROM news WHERE id = ?";
  $stmt = $pdo->prepare($sqlSel);
  $stmt->execute([$id]);
  $row = $stmt->fetch();

  if (!$row) {
    json_error("News not found", 404, 'not_found');
  }

  echo json_encode(['views' => (int)($row['views'] ?? 0)], JSON_UNESCAPED_UNICODE);

} catch (Throwable $e) {
  json_error($e->getMessage(), 500, 'server_error');
}
