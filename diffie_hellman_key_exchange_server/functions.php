<?php

function validate_request()
{
    if (
        !isset($_POST["p"]) ||
        !isset($_POST["g"]) ||
        !isset($_POST["k"]) ||
        !isset($_POST["session_id"]) ||
        !isset($_POST["action"])
    ) {
        return false;
    }

    return true;
}

function sha256($msg)
{
    return hash("sha256", $msg);
}

function random_sha256($round_count)
{
    $hash = "";
    for ($i = 0; $i < $round_count; $i++) {
        $hash .= sha256(sha1(time()));
    }
    return $hash;
}

function is_session_id_exist($session_id)
{
    global $database;

    $statement = $database->prepare('SELECT session_id FROM "secrets" WHERE "session_id" = :session_id');
	$statement->bindValue(':session_id', $session_id);
	$result = $statement->execute();

	$exist = $result->fetchArray(SQLITE3_ASSOC);

	$result->finalize();

    return $exist !== false;
}


function get_session_aes_keys($session_id)
{
    global $database;

    $statement = $database->prepare('SELECT * FROM "secrets" WHERE "session_id" = :session_id');
    $statement->bindValue(':session_id', $session_id);
    $result = $statement->execute();

    $data = $result->fetchArray(SQLITE3_ASSOC);
    $result->finalize();

    return $data;
}


function create_session_id_record($session_id)
{
    global $database;

    $statement = $database->prepare('INSERT INTO "secrets" ("session_id", "key", "iv") VALUES (:session_id, :key, :iv)');
	$statement->bindValue(':session_id', $session_id);
	$statement->bindValue(':key', '');
	$statement->bindValue(':iv', '');
	$statement->execute();
}


function update_key($session_id, $key)
{
    global $database;

    $statement = $database->prepare('UPDATE secrets SET key = :key WHERE session_id = :session_id');
	$statement->bindValue(':session_id', $session_id);
	$statement->bindValue(':key', $key);
	$statement->execute();

}

function update_iv($session_id, $iv)
{
    global $database;

    $statement = $database->prepare('UPDATE secrets SET iv = :iv WHERE session_id = :session_id');
	$statement->bindValue(':session_id', $session_id);
	$statement->bindValue(':iv', $iv);
	$statement->execute();

}

function handle_request($session_id, $shared_key, $action)
{
    if (!is_session_id_exist($session_id)) {
        create_session_id_record($session_id);
    }

    if ($action === "key") {
        update_key($session_id, $shared_key);
    } elseif ($action === "iv") {
        update_iv($session_id, $shared_key);
    }
}

function keycode($p, $g, $session_id, $client_public_key, $action)
{
    $private_key = hexdec(random_sha256(3));
    $private_key = number_format($private_key, 0, "", ""); //removes digits after .
    $private_key = gmp_init($private_key);
    $private_key = gmp_abs($private_key);
    $server_public_key = gmp_strval($g ^ $private_key % $p); //convert gmp number to string

    $shared_key = gmp_strval($client_public_key ^ $private_key % $p);
    $shared_key = md5($shared_key);

    if ($action === "iv") {
        $shared_key = substr($shared_key, -16);
    }

    handle_request($session_id, $shared_key, $action);

    return $server_public_key;
}







function Base64UrlDecode($x)
{
   return base64_decode(str_replace(array('_','-'), array('/','+'), $x));
}


function Base64UrlEncode($x)
{
   return str_replace(array('/','+'), array('_','-'), base64_encode($x));
}



function encrypt_aes256($clear_text, $key, $iv) {
    $iv = str_pad($iv, 16, "\0");
    $encrypt_text = openssl_encrypt($clear_text, "AES-256-CBC", $key, OPENSSL_RAW_DATA, $iv);
    $data = Base64UrlEncode($encrypt_text);
    return $data;
}

function decrypt_aes256($data, $key, $iv) {
    $iv = str_pad($iv, 16, "\0");
    $encrypt_text = Base64UrlDecode($data);
    $clear_text = openssl_decrypt($encrypt_text, "AES-256-CBC", $key, OPENSSL_RAW_DATA, $iv);
    return $clear_text;
}


function decrypt_file_aes256($filePath, $saveLocation, $key, $iv) {
    $fileBuffer = file_get_contents($filePath);
    $iv = str_pad($iv, 16, "\0");
    $cipher = base64_decode($fileBuffer);
    $plain = openssl_decrypt($cipher, "AES-256-CBC", $key, OPENSSL_RAW_DATA, $iv);
    file_put_contents($saveLocation, $plain);
}

function encrypt_file_aes256($filePath, $saveLocation, $key, $iv) {
    $fileBuffer = file_get_contents($filePath);
    $iv = str_pad($iv, 16, "\0");
    $cipher = openssl_encrypt($fileBuffer, "AES-256-CBC", $key, OPENSSL_RAW_DATA, $iv);
    $cipher64 = base64_encode($cipher);
    file_put_contents($saveLocation, $cipher64);
}