<?php
// ==============================================
// TEST FILE: Intentionally Vulnerable PHP Code
// Used for testing the PHP Security Scanner
// DO NOT use this code in production!
// ==============================================

// SQL Injection vulnerabilities
$id = $_GET['id'];
$result = mysql_query("SELECT * FROM users WHERE id=" . $_GET['id']);
$result2 = mysqli_query($conn, "SELECT * FROM users WHERE name='" . $_POST['name'] . "'");
$stmt = $pdo->query($userInput);
$query = "SELECT * FROM products WHERE category='" . $_REQUEST['cat'] . "'";
$escaped = mysql_real_escape_string($_GET['input']);
$safe = addslashes($_GET['value']);

// XSS vulnerabilities
echo $_GET['search'];
print $_POST['username'];
?>
<div><?= $_REQUEST['name'] ?></div>
<?php
echo $unsanitizedVar;
$html = "<div>" . innerHTML = $_GET['data'];
echo htmlspecialchars($input, ENT_COMPAT);

// Command Injection
exec("ping " . $_GET['host']);
system("ls " . $_POST['dir']);
passthru("cat " . $_REQUEST['file']);
shell_exec("grep " . $_GET['pattern']);
$output = `whoami $_GET['cmd']`;
popen("tail -f " . $_POST['logfile'], "r");
proc_open("cmd " . $_REQUEST['arg'], $descriptors, $pipes);
exec("convert " . $userFile);
eval("return " . $_GET['expr'] . ";");

// File Inclusion
include($_GET['page']);
require($userInput);
include_once("templates/" . $_GET['tpl'] . ".php");

// Path Traversal
$content = file_get_contents($_GET['file']);
$fp = fopen($_POST['path'], 'r');
unlink($_REQUEST['delete']);
file_put_contents($_GET['output'], $data);
readfile($_POST['download']);
copy($_REQUEST['src'], $_REQUEST['dst']);
mkdir($_GET['dirname']);

// Insecure Deserialization
$obj = unserialize($_COOKIE['session_data']);
$data = unserialize($rawInput);
$config = unserialize(file_get_contents('config.dat'));

// SSRF
curl_setopt($ch, CURLOPT_URL, $_GET['url']);
$response = file_get_contents("https://" . $_GET['domain'] . "/api");
$ch = curl_init($_REQUEST['target']);
curl_setopt($ch, CURLOPT_URL, $apiEndpoint);

// Weak Cryptography
$hash = md5($password);
$hash2 = sha1($password_input);
$checksum = md5($data);
$sig = sha1($content);
$random = rand(1, 100);
$token = mt_rand();
$encrypted = mcrypt_encrypt(MCRYPT_DES, $key, $data, MCRYPT_MODE_ECB);
$cipher = mcrypt_module_open('des', '', 'ecb', '');

// Authentication & Credentials
$password = 'SuperSecret123!';
$api_key = 'sk-1234567890abcdef';
$db_password = "root123";
ini_set('session.use_only_cookies', 0);
ini_set('session.cookie_httponly', 0);
ini_set('session.cookie_secure', 0);
session_regenerate_id();
$token = $_COOKIE['auth_token'];

// Hardcoded DB connection
$conn = mysqli_connect('localhost', 'root', 'password123', 'mydb');

// Hardcoded tokens
$access_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0';
$refresh_token = 'rt_abcdef123456789012345678';

// AWS credentials
$aws_key = 'AKIAIOSFODNN7EXAMPLE';
$aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

// Private key
$key = '-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds...
-----END RSA PRIVATE KEY-----';

// SMTP credentials
$smtp_password = 'mail_pass_123';

// Connection string
$dsn = "mysql://admin:s3cret@db.example.com:3306/production";

// App secrets
$client_secret = 'cs_abcdef123456789012345';
$encryption_key = 'enc_key_super_secret_value_here';

// Base64 obfuscated
$decoded = base64_decode('c3VwZXJfc2VjcmV0X3Bhc3N3b3Jk');

// Information Disclosure
phpinfo();
error_reporting(E_ALL);
ini_set('display_errors', 'On');
var_dump($sensitiveData);
print_r($userObject);
$debug = true;
// TODO: remove this before deployment
// FIXME: security issue here

// File Upload
move_uploaded_file($_FILES['avatar']['tmp_name'], $uploadDir . $_FILES['avatar']['name']);
$filename = $_FILES['upload']['name'];
$type = $_FILES['upload']['type'];
copy($tmpFile, $_FILES['doc']['name']);

// CSRF
?>
<form method="post" action="/transfer">
    <input type="hidden" name="amount" value="1000">
</form>
<?php
$amount = $_POST['amount'];

// Open Redirect
header("Location: " . $_GET['redirect']);
header("Location: " . $returnUrl);

// XXE
$xml = simplexml_load_string($xmlInput);
$doc = new DOMDocument();
$doc->loadXML($externalData);
libxml_disable_entity_loader(false);
$rss = simplexml_load_file($_GET['feed']);
$xml = simplexml_load_string($data, 'SimpleXMLElement', LIBXML_NOENT);

// Insecure Configuration
ini_set('allow_url_fopen', 'On');
ini_set('allow_url_include', 1);
// register_globals = On
// magic_quotes_gpc = On
ini_set('expose_php', 'On');
ini_set('session.use_trans_sid', 1);
ini_set('session.cookie_samesite', 'None');
?>
