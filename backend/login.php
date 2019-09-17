<?php
//include database configuration
include("config.php");
//start session
session_start();

//check if input fields contain data or not 
if (!isset($_POST['email'], $_POST['password'])) {
    // Could not get the data that should have been sent.
    die('Please fill both the email and password field!');
}

// Using prepered SQL statements to prevent SQL injection
if ($stmt = $db->prepare('SELECT id, name, password FROM users WHERE email = ?')) {
    $stmt->bind_param('s', $_POST['email']);
    $stmt->execute();
    // Store the result so we can check if the account exists in the database.
    $stmt->store_result();
}
if ($stmt->num_rows > 0) {
    $stmt->bind_result($id, $name, $password);
    $stmt->fetch();
    // Account exists, now we verify the password.
    // Note: remember to use password_hash in your registration file to store the hashed passwords.
    if (password_verify($_POST['password'], $password)) {
        session_regenerate_id();
        $_SESSION['loggedin'] = TRUE;
        $_SESSION['name'] = $name;
        $_SESSION['email'] = $_POST['email'];
        $_SESSION['id'] = $id;
        echo 'Welcome ' . $_SESSION['name'] . '!';
    } else {
        echo 'Incorrect password!';
    }
} else {
    echo 'Incorrect email!';
}
$stmt->close();
