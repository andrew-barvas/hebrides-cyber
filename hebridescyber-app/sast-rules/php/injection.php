<?php
// Annotated test cases for injection.yaml (run: opengrep test sast-rules/).

$conn = mysqli_connect("localhost", "app", getenv("DB_PASSWORD"), "shop");

$id = $_GET['id'];
// ruleid: php-sql-injection
$result = mysqli_query($conn, "SELECT * FROM products WHERE id = " . $id);
// ruleid: php-sql-injection
$result = mysqli_query($conn, "SELECT * FROM users WHERE name = '{$_POST['name']}'");
// ok: php-sql-injection
$result = mysqli_query($conn, "SELECT * FROM products WHERE id = " . intval($id));
// ok: php-sql-injection
$result = mysqli_query($conn, "SELECT * FROM products WHERE id = " . (int) $_GET['id']);
// ok: php-sql-injection
$safe = mysqli_real_escape_string($conn, $_GET['q']);
$result = mysqli_query($conn, "SELECT * FROM products WHERE name = '" . $safe . "'");
// ok: php-sql-injection
$result = mysqli_query($conn, "SELECT COUNT(*) FROM products");

$pdo = new PDO("mysql:host=localhost;dbname=shop", "app", getenv("DB_PASSWORD"));
$email = $_POST['email'];
// ruleid: php-sql-injection-pdo
$stmt = $pdo->query("SELECT * FROM users WHERE email = '$email'");
// ruleid: php-sql-injection-pdo
$stmt = $pdo->prepare("SELECT * FROM users WHERE email = '" . $email . "'");
// ok: php-sql-injection-pdo
$stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
$stmt->execute([$email]);
// ok: php-sql-injection-pdo
$stmt = $pdo->query("SELECT * FROM users WHERE email = " . $pdo->quote($email));

function laravel_controller($request) {
    // ok: php-sql-injection-pdo
    $term = $request->query('term');
    // ruleid: php-sql-injection-framework
    $rows = DB::select("SELECT * FROM posts WHERE title LIKE '%" . $term . "%'");
    // ok: php-sql-injection-framework
    $rows = DB::select("SELECT * FROM posts WHERE title LIKE ?", ['%' . $term . '%']);
    return $rows;
}

global $wpdb;
// ruleid: php-sql-injection-framework
$posts = $wpdb->get_results("SELECT * FROM wp_posts WHERE post_author = " . $_GET['author']);
// ok: php-sql-injection-framework
$posts = $wpdb->get_results($wpdb->prepare("SELECT * FROM wp_posts WHERE post_author = %d", $_GET['author']));

// ruleid: php-code-injection
eval('$x = ' . $_GET['expr'] . ';');
// ruleid: php-code-injection
call_user_func($_REQUEST['action']);
// ok: php-code-injection
eval('$x = 1 + 1;');
$action = $_GET['action'];
if (in_array($action, ['list', 'show'], true)) {
    // ok: php-code-injection
    call_user_func($action);
}

$host = $_GET['host'];
// ruleid: php-command-injection
system("ping -c 1 " . $host);
// ruleid: php-command-injection
$out = shell_exec("nslookup $host");
// ok: php-command-injection
system("ping -c 1 " . escapeshellarg($host));
// ok: php-command-injection
exec("uptime");

// ruleid: php-file-inclusion
include $_GET['page'] . ".php";
$tpl = $_REQUEST['tpl'];
// ruleid: php-file-inclusion
require_once("templates/" . $tpl);
// ok: php-file-inclusion
include "pages/" . basename($_GET['page']) . ".php";
// ok: php-file-inclusion
require_once __DIR__ . "/config.php";

// ruleid: php-unserialize-untrusted
$cart = unserialize(base64_decode($_COOKIE['cart']));
// ok: php-unserialize-untrusted
$cart = unserialize($_COOKIE['cart'], ['allowed_classes' => false]);
// ok: php-unserialize-untrusted
$cart = json_decode($_COOKIE['cart'], true);
