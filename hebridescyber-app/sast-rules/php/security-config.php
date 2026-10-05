<?php
// Annotated test cases for security-config.yaml (run: opengrep test sast-rules/).
use GuzzleHttp\Client;

$ch = curl_init("https://partner.example/api");
// ruleid: php-tls-verification-disabled
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
// ruleid: php-tls-verification-disabled
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
// ok: php-tls-verification-disabled
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
// ok: php-tls-verification-disabled
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

// (an array match is reported on the line the array starts)
// ruleid: php-tls-verification-disabled
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_SSL_VERIFYPEER => false,
]);

$context = stream_context_create([
    // ruleid: php-tls-verification-disabled
    'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
]);

// ruleid: php-tls-verification-disabled
$client = new Client(['base_uri' => 'https://partner.example', 'verify' => false]);
// ok: php-tls-verification-disabled
$client = new Client(['base_uri' => 'https://partner.example', 'verify' => '/etc/ssl/private-ca.pem']);
