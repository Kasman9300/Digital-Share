<?php
$host = "localhost";
$user = "root";
$pass = ""; // tomt password i XAMPP som standard
$db   = "havn_db";

$conn = new mysqli($host, $user, $pass, $db);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

echo "Connected successfully!";
?>