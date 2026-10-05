<?php
// Annotated test cases for open-redirect.yaml (run: opengrep test sast-rules/).

$next = $_GET['next'];
// ruleid: php-open-redirect
header("Location: " . $next);
exit;

// ruleid: php-open-redirect
wp_redirect($_REQUEST['redirect_to']);

// ok: php-open-redirect
header("Location: /login.php?next=" . urlencode($next));

// ok: php-open-redirect
header("Location: /dashboard.php");

// ok: php-open-redirect
wp_safe_redirect($_REQUEST['redirect_to']);

$target = $_GET['to'];
if (is_safe_redirect_target($target)) {
    // ok: php-open-redirect
    header("Location: " . $target);
}

// ok: php-open-redirect
header("X-Requested-Page: " . $_GET['page']);
