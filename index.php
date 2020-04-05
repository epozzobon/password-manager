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


?><html>
  <head>
    <title>Password Manager</title>
    <style>
.index {
  text-align: center;
}
.secret {
  color: #000;
  background-color: #000;
  width: 10em;
}
th {
  text-align: left;
}
td,th {
  border: 1px solid black;
  padding: .4em;
}
div#edit_window {
  position: fixed;
  background-color: #fff;
  margin: 5em;
  top: 0em;
  left: 0em;
  border: 1px solid green;
  padding: 1em;
}
    </style>

  </head>
<body>

  <div id="disclaimer">
    <h1>Warning!</h1>
    <p>Before entering your password, please make sure that:</p>
    <li>You trust the device you are currently using.</li>
    <li>You trust the browser you are currently using.</li>
    <li>You trust all the browser extensions that are currently installed.</li>
    <li>You are connected to this website over HTTPS.</li>
  </div>

  <div id="password-form">
    <label for="password_field">Password:</label>
    <input id="password_field" type="password" value="" />
    <input id="decrypt_button" type="button" value="Decrypt" disabled="true" />
    <input id="upload_button" type="button" value="Encrypt, Sign and Upload" disabled="false" />
  </div>

  <div id="secrets_container" style="display: none">
  <h1>Passwords</h1>

  <table id="passwords_table">
    <tr>
      <th>Index</th>
      <th style="width: 10em;">Name</th>
      <th style="width: 10em;">Comment</th>
      <th style="width: 10em;">Secret</th>
      <th>Actions</th>
    </tr>
  </table>

  <input id="append_button" type="button" value="Add" />

  </div>

  <div id="edit_window" style="display: none;">
    <p>
      <label for="name_field">Name:</label>
      <br/>
      <input id="name_field" type="text" />
    </p>
    <p>
      <label for="comment_field">Comment:</label>
      <br/>
      <textarea id="comment_field"></textarea>
    </p>
    <p>
      <label for="secret_field">Secret:</label>
      <br/>
      <input id="secret_field" type="password" />
    </p>
    <input id="save_button" type="button" value="Save" />
    <input id="abort_button" type="button" value="Cancel" />
  </div>

  <script src="openpgp.min.js"></script>
  <script>

'use strict';

let wallet = null;
let ciphertext = null;

const user = "<?php echo $user; ?>";
const password_field = document.getElementById("password_field");
const decrypt_button = document.getElementById("decrypt_button");
const upload_button = document.getElementById("upload_button");
const passwords_table = document.getElementById("passwords_table");
const secrets_container = document.getElementById("secrets_container");
const edit_window = document.getElementById("edit_window");
const name_field = document.getElementById("name_field");
const secret_field = document.getElementById("secret_field");
const comment_field = document.getElementById("comment_field");
const save_button = document.getElementById("save_button");
const abort_button = document.getElementById("abort_button");
const append_button = document.getElementById("append_button");
const diclaimer = document.getElementById("disclaimer");


async function decrypt(data, password) {
  // No verification performed on client side, since there is no public key.
  const {signatures, data: ciphertext} = (await openpgp.verify({
    message: await openpgp.message.read(data),
    publicKeys: []
  }));
  console.log(signatures);

  const decrypted = (await openpgp.decrypt({
    message: await openpgp.message.read(ciphertext),
    passwords: [password],
    armor: false
  }));
  data = JSON.parse(decrypted.data);
  return data;
}

async function encryptSignUpload(obj, password) {
  let data = await openpgp.key.readArmored(obj.signKey);
  const signKey = data.keys[0];

  const encrypted = (await openpgp.encrypt({
    message: openpgp.message.fromText(JSON.stringify(obj)),
    passwords: [password],
    armor: false
  })).message.packets.write();

  const signed = (await openpgp.sign({
    message: openpgp.message.fromBinary(encrypted),
    privateKeys: [signKey],
    armor: false
  })).message.packets.write();

  let response = await fetch(`?user=${user}&action=upload`, {
    method: 'POST',
    cache: "no-store",
    body: signed
  });
  response = await response.text();
}

function renderWallet() {
  /* Make sure the table contains the correct number of rows */
  while (passwords_table.rows.length - 1 > wallet.passwords.length) {
    passwords_table.deleteRow(-1);
  }
  while (passwords_table.rows.length - 1 < wallet.passwords.length) {
    let row = passwords_table.insertRow(-1);
    row.insertCell(-1).classList.add('index');
    row.insertCell(-1).classList.add('name');
    row.insertCell(-1).classList.add('comment');
    row.insertCell(-1).classList.add('secret');
    let cell = row.insertCell(-1);
    cell.classList.add('actions');

    const editBtn = document.createElement('button');
    editBtn.onclick = editClick;
    editBtn.innerText = 'Edit';
    cell.appendChild(editBtn);

    const removeBtn = document.createElement('button');
    removeBtn.onclick = removeClick;
    removeBtn.innerText = 'Remove';
    cell.appendChild(removeBtn);
  }

  for (let i=0; i < wallet.passwords.length; i++) {
    const obj = wallet.passwords[i];
    const row = passwords_table.rows[1+i];

    row.cells[0].innerText = i;
    row.cells[1].innerText = obj.name;
    row.cells[2].innerText = obj.comment;
    row.cells[3].innerText = obj.secret;
  }

  secrets_container.style.display = 'block';
}

function removeClick(evt) {
  const row = evt.target.parentElement.parentElement;
  const index = parseInt(row.cells[0].innerText);
  wallet.passwords.splice(index, 1);

  renderWallet();
}

function editClick(evt) {
  const row = evt.target.parentElement.parentElement;
  const index = parseInt(row.cells[0].innerText);
  const obj = wallet.passwords[index]; 

  edit_window.style.display = 'block';
  name_field.value = obj.name;
  secret_field.value = obj.secret;
  comment_field.value = obj.comment;

  abort_button.onclick = evt => {
    edit_window.style.display = 'none';
  };

  save_button.onclick = evt => {
    edit_window.style.display = 'none';

    obj.name = name_field.value;
    obj.secret = secret_field.value;
    obj.comment = comment_field.value;

    renderWallet();
  };
}

append_button.onclick = () => {
  wallet.passwords.push({name: '', comment: '', secret: ''});
  renderWallet();
};

(async () => {
  ciphertext = new Uint8Array(
    await (
      fetch(`users/${user}/payload.gpg`, {
        cache: "no-store"
      })
        .then(response => response.arrayBuffer())
    )
  );
  
  decrypt_button.disabled = false;

  decrypt_button.onclick = () => {
    password_field.disabled = true;
    decrypt_button.disabled = true;
    const password = password_field.value;

    decrypt(ciphertext, password).then(data =>
    {
      disclaimer.style.display = 'none';
      password_field.disabled = false;
      decrypt_button.disabled = true;
      upload_button.disabled = false;

      wallet = data;
      renderWallet();

    }).catch(err =>
    {
      console.log(err);
      password_field.disabled = false;
      decrypt_button.disabled = false;
    });
  };

  upload_button.onclick = () => {
    password_field.disabled = true;
    decrypt_button.disabled = true;
    upload_button.disabled = true;
    const password = password_field.value;

    encryptSignUpload(wallet, password).then(res => {
      password_field.disabled = false;
      decrypt_button.disabled = true;
      upload_button.disabled = false;
    });
  }

})();

</script>
</body>
</html>

<?php
}
?>
