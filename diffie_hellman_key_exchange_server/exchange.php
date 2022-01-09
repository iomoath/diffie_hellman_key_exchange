<?php

# Basic implementation of Diffie–Hellman key exchange algorithm
# Fix --> Improved control & security: The session Id to be provided by the server instead


error_reporting(E_ALL);

require_once("init.php");


if(!validate_request()) 
	exit('0');




$session_id = trim($_POST['session_id']);
$p = gmp_init(trim($_POST['p']));
$g = gmp_init(trim($_POST['g']));
$client_public_key = gmp_init(trim($_POST['k']));
$action = trim($_POST['action']);


$server_public_key = keycode($p, $g, $session_id, $client_public_key, $action);

exit($server_public_key);
