<?php
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: access');
header('Access-Control-Allow-Methods: POST');
header('Content-Type: application/json; charset=UTF-8');
header('Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With');

require_once __DIR__ . '/database.php';
require_once __DIR__ . '/sendJson.php';
require_once __DIR__ . '/jwtHandler.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $data = json_decode(file_get_contents('php://input'));

    if (
        !isset($data->first_name) ||
        !isset($data->last_name) ||
        !isset($data->email) ||
        !isset($data->mobile_number) ||
        !isset($data->password) ||
        !isset($data->referral_code) ||
        empty(trim($data->first_name)) ||
        empty(trim($data->last_name)) ||
        empty(trim($data->email)) ||
        empty(trim($data->mobile_number)) ||
        empty(trim($data->referral_code)) ||
        empty(trim($data->password))
    ) {
        sendJson(
            422,
            'Please fill all the required fields & None of the fields should be empty.',
            ['required_fields' => ['first_name', 'last_name', 'email', 'mobile_number','referral_code', 'password']]
        );
    }

    $first_name = mysqli_real_escape_string($connection, htmlspecialchars(trim($data->first_name)));
    $last_name = mysqli_real_escape_string($connection, htmlspecialchars(trim($data->last_name)));
    $email = mysqli_real_escape_string($connection, trim($data->email));
    $mobile_number = mysqli_real_escape_string($connection, trim($data->mobile_number));
    $referral_code = mysqli_real_escape_string($connection, trim($data->referral_code));
    $password = trim($data->password);

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        sendJson(422, 'Invalid Email Address!');
    } 

    // Check if email or mobile_number already exists
    $stmt = $connection->prepare("SELECT `email`, `mobile_number` FROM `users` WHERE `email` = ? OR `mobile_number` = ?");
    $stmt->bind_param("ss", $email, $mobile_number);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        sendJson(422, 'This E-mail or Mobile Number already in use!');
    }

    $stmt->close();

    // Insert user into the database
    $hash_password = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $connection->prepare("INSERT INTO `users`(`first_name`,`last_name`,`email`,`mobile_number`,`referral_code`,`password`) VALUES(?, ?, ?, ?, ?,?)");
    $stmt->bind_param("ssssss", $first_name, $last_name, $email, $mobile_number, $referral_code, $hash_password);
    $result = $stmt->execute();
    $stmt->close();

    if ($result) {
        $sql = "SELECT * FROM users WHERE email = '$email' OR mobile_number = '$email'";
        $query = mysqli_query($connection, $sql);
        $row = mysqli_fetch_array($query, MYSQLI_ASSOC);

        // Return the token in the response
        sendJson(201, 'You have successfully registered.', [
            'token' => encodeToken($row['id'])
        ]);
    } else {
        sendJson(500, 'Something went wrong.');
    }
}

sendJson(405, 'Invalid Request Method. HTTP method should be POST');
?>
