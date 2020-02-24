<?php
session_start();

if (isset($_REQUEST['foo'])) {
   $_SESSION['foo'] = $_REQUEST['foo'];
}
echo $_SESSION['foo'];
?>
<hr/>
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
<input name=foo>
<input name=file type=file>
<input type=submit>
</form>
