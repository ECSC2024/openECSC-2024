<?php
session_start();

include_once('header.php');
include_once('db.php');

if (!isset($_SESSION['files']) || !is_array($_SESSION['files'])) {
    echo '<h3>No files uploaded yet, start using our service <a href="/upload.php">here</a>.</h3>';
} else {
?>
    <h4>Your uploaded files:</h4>
    <ul class="list-group my-3 mx-auto col-md-6">
    <?php

        $db = db_connect();
        foreach ($_SESSION['files'] as $fileid) {
            $sql = "SELECT * FROM files WHERE id = '$fileid'";
            $row = $db->querySingle($sql, true);
            if (is_array($row) && count($row) > 0){
                $filename = htmlspecialchars($row['filename']);

                $size = $row['size'];
                if ($size < 1024) {
                    $size = $size . ' B';
                } elseif ($size < 1048576) {
                    $size = round($size / 1024, 2) . ' KB';
                } else {
                    $size = round($size / 1048576, 2) . ' MB';
                }

                echo "<li id=\"$fileid\" class=\"list-group-item d-flex justify-content-between align-items-center\">";
                echo "$filename ($size)";
                echo '<span class="ms-auto  badge bg-primary" onclick="copylink()"><i class="bi bi-clipboard-fill"></i></span>';
                echo '<a href="/download.php?id='.$fileid.'" class="mx-1 badge bg-primary" download="'.$filename.'">';
                echo '<i class="bi bi-download"></i></a>';
                echo "</li>";
            } else {
                echo "<li class=\"list-group-item d-flex justify-content-between align-items-center\">Too late, file removed</li>";
            }
        }
        ?>
    </ul>



<div class="position-fixed bottom-0 end-0 p-3" style="z-index: 11">
  <div id="toastmsg" class="toast hide" role="alert" aria-live="assertive" aria-atomic="true">
    <div class="toast-header">
      <span class="mx-auto">Link copied!</span>
    </div>
  </div>
</div>


<script>
    function copylink() {
        var id = event.target.parentElement.parentElement.id;
        var url = window.location.origin + '/download.php?id=' + id;
        navigator.clipboard.writeText(url);
        bootstrap.Toast.getOrCreateInstance(document.getElementById('toastmsg')).show();
    }
</script>

<?php
}

include_once('footer.php');
?>