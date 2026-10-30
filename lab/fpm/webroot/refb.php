<?php
/* Lab-only benign session builder: d/a with no R:N. */
session_start();
$_SESSION = array();
$_SESSION['d'] = 'pad';
$_SESSION['a'] = 'x';
echo "REFB_OK\n";
