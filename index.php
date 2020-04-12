<?php

/* Force HTTPS */
if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== "on") {
  http_response_code(400);
  die("please access this over https");
}

if (!isset($_REQUEST['user'])) {
  http_response_code(400);
  die("user not given");
}
$user = preg_replace('/[^A-Za-z0-9_\-]/', '_', $_REQUEST['user']);
if (!file_exists("users/$user/public.gpg")) {
  http_response_code(404);
  die("user $user doesn't exists");
}

if (array_key_exists('action', $_REQUEST) && $_REQUEST['action'] === 'upload') {

  /* when the user uploads data, we want to check the PGP signature to prevent
   * an attacker from just overwriting the password database.
   */
  $cwd = getcwd();
  putenv("GNUPGHOME=$cwd/.gnupg/");

  $gpg = new gnupg();
  $gpg->setarmor(1);

  $public_key = file_get_contents("users/$user/public.gpg");
  $info = $gpg->import($public_key);
  if (FALSE === $info) {
    http_response_code(500);
    die("error importing the key");
  }
  $user_fingerprint = $info['fingerprint'];

  $payload = file_get_contents('php://input');

  $info = $gpg->verify($payload, false, $plaintext);
  if (FALSE === $info) {
    http_response_code(500);
    die("error verifying the signature");
  }

  $verified = FALSE;
  foreach ($info as $signature) {
    if ($user_fingerprint === $signature['fingerprint']) {
      $verified = $signature['timestamp'];
    }
  }
  if ($verified === FALSE) {
    http_response_code(401);
    die("key fingerprint does not match");
  }

  file_put_contents("users/$user/payload.gpg", $payload);
  http_response_code(200);
  echo "Success!";
  exit(0);

} else {
	readfile('password_manager.html');
}
?>
