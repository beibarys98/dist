<?php
declare(strict_types=1);

require_once __DIR__ . '/db.php';

try {
  $pdo  = db();
  $lang = get_lang();

  $id    = get_int('id', 0);
  $limit = get_int('limit', 0);
  if ($limit <= 0) $limit = 50;
  if ($limit > 200) $limit = 200;

  $TABLE = 'career_events';

  $cols = [];
  $st = $pdo->query("SHOW COLUMNS FROM `$TABLE`");
  foreach ($st->fetchAll() as $row) {
    $cols[$row['Field']] = true;
  }
  $has = fn(string $c): bool => isset($cols[$c]);

  $titleCol = $has("title_{$lang}") ? "title_{$lang}" : ($has('title') ? 'title' : null);
  $bodyCol  = $has("body_{$lang}")  ? "body_{$lang}"  : ($has('body')  ? 'body'  : null);

  $publishedCol = $has('published_at') ? 'published_at' : ($has('created_at') ? 'created_at' : null);

  $isPublishedCol = $has('is_published') ? 'is_published' : null;

  $imageCol = null;
  foreach (['image_url', 'image', 'image_path', 'cover', 'cover_image', 'photo', 'photo_path'] as $c) {
    if ($has($c)) { $imageCol = $c; break; }
  }

  $videoCol = null;
  foreach (['video_url', 'video', 'video_path', 'media_url', 'media', 'file_url', 'file_path'] as $c) {
    if ($has($c)) { $videoCol = $c; break; }
  }

  $select = [];
  $select[] = "t.id AS id";
  $select[] = $titleCol ? "t.`{$titleCol}` AS title" : "'' AS title";
  $select[] = $bodyCol  ? "t.`{$bodyCol}` AS body"   : "'' AS body";
  $select[] = $publishedCol ? "t.`{$publishedCol}` AS published_at" : "NULL AS published_at";
  $select[] = $imageCol ? "t.`{$imageCol}` AS image_url" : "'' AS image_url";
  $select[] = $videoCol ? "t.`{$videoCol}` AS video_url" : "'' AS video_url";

  $sql = "SELECT " . implode(", ", $select) . " FROM `$TABLE` t";

  $where  = [];
  $params = [];

  if ($id > 0) {
    $where[] = "t.id = :id";
    $params[':id'] = $id;
  }

  if ($isPublishedCol) {
    $where[] = "t.`{$isPublishedCol}` = 1";
  }

  if ($where) {
    $sql .= " WHERE " . implode(" AND ", $where);
  }

  if ($publishedCol) {
    $sql .= " ORDER BY t.`{$publishedCol}` DESC, t.id DESC";
  } else {
    $sql .= " ORDER BY t.id DESC";
  }

  if ($id <= 0) {
    $sql .= " LIMIT :limit";
  }

  $stmt = $pdo->prepare($sql);

  foreach ($params as $k => $v) {
    $stmt->bindValue($k, $v, PDO::PARAM_INT);
  }
  if ($id <= 0) {
    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
  }

  $stmt->execute();
  $rows = $stmt->fetchAll();

  $BASE = 'https://q-creative.media';

  $toAbs = function ($v) use ($BASE): string {
    $v = trim((string)$v);
    if ($v === '') return '';

    if (preg_match('~^https?://~i', $v)) return $v;

    if ($v[0] !== '/') $v = '/' . $v;

    return $BASE . $v;
  };

  foreach ($rows as &$r) {
    $r['id'] = (int)($r['id'] ?? 0);
    $r['title'] = (string)($r['title'] ?? '');
    $r['body']  = (string)($r['body'] ?? '');

    $r['published_at'] = $r['published_at'] ? (string)$r['published_at'] : null;

    $r['image_url'] = $toAbs($r['image_url'] ?? '');
    $r['video_url'] = $toAbs($r['video_url'] ?? '');
  }
  unset($r);

  echo json_encode($rows, JSON_UNESCAPED_UNICODE);

} catch (Throwable $e) {
  json_error($e->getMessage(), 500, 'server_error');
}
