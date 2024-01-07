<?php
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: access, Authorization');
header('Access-Control-Allow-Methods: POST');
header('Content-Type: application/json; charset=UTF-8');
header('Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With');

require_once __DIR__ . '/database.php';
require_once __DIR__ . '/sendJson.php';
require_once __DIR__ . '/jwtHandler.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Get the token from the headers
    $token = isset(getallheaders()['Authorization']) ? getallheaders()['Authorization'] : '';
    $token = str_replace("Bearer ", "", $token);
    // Verify the token
    $user_id = decodeToken($token);

    if (!$user_id) {
        sendJson(401, 'Unauthorized. Invalid or missing token.');
    }

    $data = $_POST;

    // Sanitize and escape input data
    $first_name = isset($data['first_name']) ? mysqli_real_escape_string($connection, htmlspecialchars(trim($data['first_name']))) : '';
    $last_name = isset($data['last_name']) ? mysqli_real_escape_string($connection, htmlspecialchars(trim($data['last_name']))) : '';

    // Update user information
    $updateFields = [];
    if (!empty($first_name)) {
        $updateFields[] = "`first_name` = '$first_name'";
    }
    if (!empty($last_name)) {
        $updateFields[] = "`last_name` = '$last_name'";
    }

    if (!empty($updateFields)) {
        $updateQuery = "UPDATE `users` SET " . implode(', ', $updateFields) . " WHERE `id` = '$user_id'";
        $updateResult = mysqli_query($connection, $updateQuery);

        if ($updateResult) {
            sendJson(200, 'User information updated successfully.');
        } else {
            sendJson(500, 'Error updating user information.');
        }
    } else {
        sendJson(422, 'No valid fields provided for update.');
    }
}

sendJson(405, 'Invalid Request Method. HTTP method should be POST');
?>
