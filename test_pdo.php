<?php
declare(strict_types=1);

try {
    $pdo = new PDO(
        'mysql:host=10.0.0.41;port=3307;dbname=data_news;charset=utf8mb4',
        'admin',
        'StrongPassword123!',
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]
    );

    echo "Connected! Server info: " . $pdo->getAttribute(PDO::ATTR_CONNECTION_STATUS) . PHP_EOL;
} catch (Throwable $e) {
    echo "DB connection failed: " . $e->getMessage() . PHP_EOL;
}

