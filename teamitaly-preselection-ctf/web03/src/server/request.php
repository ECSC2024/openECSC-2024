<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $path = $_POST['path'];
    $method = escapeshellarg($_POST['method']);


    if ($path[0] === '/') {
        $path = substr($path, 1);
    }
    $url = escapeshellarg('http://' . getenv('API_HOST') . '/' . $path);
    
    $cmd = "curl -X $method $url";

    if (isset($_POST['headers']) && !empty($_POST['headers']) && is_array($_POST['headers'])) {
        foreach ($_POST['headers'] as $header) {
            $header = escapeshellarg($header);
            $cmd .= " -H $header";
        }
    }

    if (isset($_POST['body']) && !empty($_POST['body'])) {
        $body = escapeshellarg($_POST['body']);
        $cmd .= " -d $body";
    }

    $output = shell_exec($cmd);
    
    if ($output === null) {
        echo "Error executing the shell command.";
    } else {
        echo $output;
    }
    
    exit;
}
?>