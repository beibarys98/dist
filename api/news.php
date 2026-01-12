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

  static $cols = null;
  if ($cols === null) {
    $cols = [];
    $st = $pdo->query("SHOW COLUMNS FROM news");
    foreach ($st->fetchAll() as $row) {
      $cols[$row['Field']] = true;
    }
  }

  $has = fn(string $c): bool => isset($cols[$c]);

  $titleCol = $has("title_{$lang}") ? "title_{$lang}" : ($has('title') ? 'title' : null);
  $bodyCol  = $has("body_{$lang}")  ? "body_{$lang}"  : ($has('body')  ? 'body'  : null);

  $catCol = $has("category_{$lang}") ? "category_{$lang}" : ($has('category') ? 'category' : null);

  $publishedCol = $has('published_at') ? 'published_at' : ($has('created_at') ? 'created_at' : null);

  $isPublishedCol = $has('is_published') ? 'is_published' : null;

  $viewsCol = $has('views') ? 'views' : null;
  $likesCol = $has('likes') ? 'likes' : null;

  $selectParts = ["n.id AS id"];
  $selectParts[] = $titleCol ? "n.`{$titleCol}` AS title" : "'' AS title";
  $selectParts[] = $bodyCol ? "n.`{$bodyCol}` AS body" : "'' AS body";
  $selectParts[] = $catCol ? "n.`{$catCol}` AS category" : "'' AS category";
  $selectParts[] = $publishedCol ? "n.`{$publishedCol}` AS published_at" : "NULL AS published_at";
  $selectParts[] = $viewsCol ? "n.`{$viewsCol}` AS views" : "0 AS views";
  $selectParts[] = $likesCol ? "n.`{$likesCol}` AS likes" : "0 AS likes";

  $sql = "SELECT " . implode(", ", $selectParts) . " FROM news n";

  $where = [];
  $params = [];

  if ($isPublishedCol) {
    $where[] = "n.`{$isPublishedCol}` = 1";
  }

  if ($id > 0) {
    $where[] = "n.id = :id";
    $params[':id'] = $id;
  }

  if (!empty($where)) {
    $sql .= " WHERE " . implode(" AND ", $where);
  }

  if ($publishedCol) {
    $sql .= " ORDER BY n.`{$publishedCol}` DESC, n.id DESC";
  } else {
    $sql .= " ORDER BY n.id DESC";
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



  $hasNewsMedia = false;
  try {
    $pdo->query("SELECT 1 FROM news_media LIMIT 1");
    $hasNewsMedia = true;
  } catch (Throwable $e) {
    $hasNewsMedia = false;
  }

  if ($hasNewsMedia && count($rows) > 0) {
    $ids = array_map(fn($r) => (int)$r['id'], $rows);
    $ids = array_values(array_unique(array_filter($ids)));

    if (count($ids) > 0) {
      $in = implode(',', array_fill(0, count($ids), '?'));

      $mcols = [];
      $st2 = $pdo->query("SHOW COLUMNS FROM news_media");
      foreach ($st2->fetchAll() as $r) $mcols[$r['Field']] = true;

      $mHas = fn(string $c): bool => isset($mcols[$c]);

      if ($mHas('news_id')) {
        $mSelect = [];
        $mSelect[] = "id";
        $mSelect[] = "news_id";
        $mSelect[] = $mHas('type') ? "type" : "'' AS type";
        $mSelect[] = $mHas('file_path') ? "file_path" : "'' AS file_path";
        $mSelect[] = $mHas('mime_type') ? "mime_type" : "'' AS mime_type";

        $mSql = "SELECT " . implode(", ", $mSelect) . " FROM news_media WHERE news_id IN ($in) ORDER BY id ASC";
        $mStmt = $pdo->prepare($mSql);
        $mStmt->execute($ids);
        $mediaRows = $mStmt->fetchAll();

        $byNews = [];
        foreach ($mediaRows as $m) {
          $nid = (int)$m['news_id'];
          unset($m['news_id']);
          $byNews[$nid][] = $m;
        }

        foreach ($rows as &$r) {
          $nid = (int)$r['id'];
          $r['media'] = $byNews[$nid] ?? [];
        }
        unset($r);
      } else {
        foreach ($rows as &$r) $r['media'] = [];
        unset($r);
      }
    }
  } else {
    foreach ($rows as &$r) $r['media'] = [];
    unset($r);
  }

  echo json_encode($rows, JSON_UNESCAPED_UNICODE);

} catch (Throwable $e) {
  json_error($e->getMessage(), 500, 'server_error');
}
