<?php
declare(strict_types=1);

require_once __DIR__ . '/db.php'; // путь к твоему db.php

header('Content-Type: application/json; charset=utf-8');

try {
    $pdo = db(); // функция из твоего db.php
    echo json_encode(['success' => true, 'message' => 'Connected to DB!']);
} catch (Throwable $e) {
    echo json_encode(['error' => 'db_connect_error', 'message' => $e->getMessage()]);
}
