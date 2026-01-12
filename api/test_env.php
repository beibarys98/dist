<?php
$envPath = dirname(__DIR__) . '/.env';
if (!file_exists($envPath)) {
    die("No .env found at: $envPath");
} else {
    echo "Found .env at: $envPath\n";
    $env = parse_ini_file($envPath, false, INI_SCANNER_RAW);
    print_r($env);
}

