<?php
/* php2shell FPM laboratory — builder-page stand-in for an application that
 * stores a reference in $_SESSION.  Produces a session file whose php
 * serializer output contains `R:2` (dummy key shifts the reference index),
 * used by the consumer as the R:N hook whose target index is forged through
 * the BG(unserialize) reuse.  Lab-only scaffold.
 */
session_start();
$_SESSION = array();
$_SESSION['d'] = 'pad';
$_SESSION['a'] = 'x';
$_SESSION['r'] =& $_SESSION['a'];
echo "REF_OK\n";
