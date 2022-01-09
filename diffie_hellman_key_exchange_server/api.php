<?php

error_reporting(E_ALL);
require_once("init.php");


if(!isset($_SERVER['HTTP_SESSIONID']) || !isset($_POST['data']))
{
	// Handle invalid requests
	exit('0');
}


$session_id = $_SERVER['HTTP_SESSIONID'];
$cipher = $_POST['data'];

$keys = get_session_aes_keys($session_id);

$key = $keys['key'];
$iv = $keys['iv'];

$message = decrypt_aes256($cipher, $key, $iv);

# Encrypt the message
# $message = encrypt_aes256($message, $key, $iv);
# exit($message);
exit($message);