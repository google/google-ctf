<?php
session_start();

if (isset($_REQUEST['session_data'])) {
   $_SESSION['session_data'] = $_REQUEST['session_data'];
}
?>
<pre>
<?php
if (isset($_FILES['file'])) {
   print_r($_FILES['file']);
   $filename = uniqid('file_', true);
   echo $filename;
   move_uploaded_file($_FILES['file']['tmp_name'], '/mnt/disks/uploads/'. $filename);
}
?>
</pre>
<hr/>
<form method=post enctype=multipart/form-data>
<input name=session_data value="<?=$_SESSION['session_data'];?>">
<input name=file type=file>
<input type=submit>
</form>
<hr/>
<?php
  phpinfo();
?>
