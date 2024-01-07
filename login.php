<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: access");
header("Access-Control-Allow-Methods: POST");
header("Content-Type: text/plain; charset=UTF-8");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

require_once __DIR__ . '/database.php';
require_once __DIR__ . '/jwtHandler.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') :
    
    $data = $_POST;
    if (
        !isset($data['email']) ||
        !isset($data['password']) ||
        empty(trim($data['email'])) ||
        empty(trim($data['password']))
    ) :
        sendJson(
            422,
            'Please fill all the required fields & None of the fields should be empty.',
            ['required_fields' => ['email', 'password']]
        );
    endif;


    $email = mysqli_real_escape_string($connection, trim($data['email']));
    $password = trim($data['password']);

    $sql = "SELECT * FROM users WHERE email = '$email' OR mobile_number = '$email'";
    $query = mysqli_query($connection, $sql);
    $row = mysqli_fetch_array($query, MYSQLI_ASSOC);
    if ($row === null) sendJson(404, 'User not found!');
    if (!password_verify($password, $row['password'])) sendJson(401, 'Incorrect Password!');
    sendJson(200, '', [
        'token' => encodeToken($row['id'])
    ]);
endif;

sendJson(405, 'Invalid Request Method. HTTP method should be POST');