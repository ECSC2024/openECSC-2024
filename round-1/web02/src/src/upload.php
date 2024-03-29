<?php
session_start();

include_once('header.php');
include_once('db.php');

if( isset($_FILES['file']) ) {
    $target_dir = "/uploads/";

    $fileid = bin2hex(random_bytes(15));
    $target_file = $target_dir . $fileid;

    $type = $_FILES["file"]["type"];
    // I don't like the letter 'h'
    if ($type == "" || preg_match("/h/i", $type) == 1){
        $type = "text/plain";
    }

    $db = db_connect();
    $stmt = $db->prepare('INSERT INTO files (id, filename, content_type, size) VALUES (?, ?, ?, ?)');
    $stmt->bindParam(1, $fileid);
    $stmt->bindParam(2, $_FILES["file"]["name"]);
    $stmt->bindParam(3, $type);
    $stmt->bindParam(4, $_FILES["file"]["size"]);
    $stmt->execute();
    $db->close();

    if (move_uploaded_file($_FILES["file"]["tmp_name"], $target_file)) {
        echo '<div class="alert alert-success" role="alert">The file '. htmlspecialchars( basename( $_FILES["file"]["name"])). " has been uploaded <a href=\"/download.php?id=$fileid\">here</a>.</div>";
        
    
        if (isset($_SESSION['files']) && is_array($_SESSION['files'])) {
            $_SESSION['files'][] = $fileid;
        } else {
            $_SESSION['files'] = [$fileid];
        }
    } else {
        echo '<div class="alert alert-danger" role="alert">Sorry, there was an error uploading your file.</div>';
    }
}

?>

<h2>Upload your files here</h2>

<form class="my-5 col-md-6 mx-auto" method="post" enctype="multipart/form-data">
    <div class="mb-3">
        <label for="file" class="form-label">Select the file to upload</label>
        <input class="form-control" type="file" id="file" name="file">
    </div>
    <button type="submit" class="btn btn-primary w-100">Upload</button>
</form>

<?php
include_once('footer.php');
?>