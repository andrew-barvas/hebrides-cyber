<?php
// Annotated test cases for app.yaml (run: opengrep test sast-rules/).

// ruleid: php-laravel-debug-enabled
return [
    'name' => env('APP_NAME', 'Shop'),
    'debug' => true,
    // ok: php-laravel-debug-enabled
    'logging' => ['debug' => env('LOG_DEBUG', false)],
];
