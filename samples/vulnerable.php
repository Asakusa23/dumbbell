<?php
$password = "hunter2";
$conn = mysqli_connect("localhost", "root", $password, "app");
$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
system($_GET['cmd']);
$data = unserialize($_POST['data']);
echo $_GET['name'];
$token = "example-stripe-key";
?>
