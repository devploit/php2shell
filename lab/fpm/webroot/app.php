<?php
/* php2shell FPM laboratory — "suitable application operation" stand-in.
 *
 * CVE-2026-109619 on FPM: the advisories require an application operation for
 * the session cycle.  This page is the minimal one: it starts the session
 * (decoding it post-RINIT, where an OOM leaves BG(unserialize) stale across
 * requests) and reflects the session contents (the leak channel once a
 * poisoned string lands in the session data).
 */
session_start();
header('Content-Type: text/plain; charset=binary');
$dbg_r = !empty($_SERVER['HTTP_X_DEBUG_R']);
if ($dbg_r && isset($_SESSION['r'])) {
    $early = "pre type=".gettype($_SESSION['r'])." strlen=".(is_string($_SESSION['r'])?strlen($_SESSION['r']):-1);
    if (is_string($_SESSION['r'])) { $early .= " hex=".bin2hex(substr($_SESSION['r'], 0, 64)); }
    if (!empty($_SERVER['HTTP_X_DEBUG_ADDR'])) {
        $addr = intval($_SERVER['HTTP_X_DEBUG_ADDR'], 0);
        $m = @fopen('/proc/self/mem', 'rb');
        if ($m) {
            fseek($m, $addr);
            $raw = @fread($m, 40);
            fclose($m);
            if ($raw !== false && strlen($raw) === 40) {
                $early .= " memlen=".unpack('P', substr($raw, 16, 8))[1]
                       . " memval=".bin2hex(substr($raw, 24, 16));
            } else { $early .= " memread_fail"; }
        }
    }
    file_put_contents('/tmp/p2s_dbg.txt', $early."\n", FILE_APPEND);
}
if (!empty($_SERVER['HTTP_X_ECHO_DELAY'])) {
    usleep((int)$_SERVER['HTTP_X_ECHO_DELAY']);
}
if ($dbg_r && isset($_SESSION['r'])) {
    $mid = "mid type=".gettype($_SESSION['r'])." strlen=".(is_string($_SESSION['r'])?strlen($_SESSION['r']):-1);
    file_put_contents('/tmp/p2s_dbg.txt', $mid."\n", FILE_APPEND);
}
if (!isset($_SESSION) || !is_array($_SESSION)) {
    echo "SESSION_EMPTY\n";
    exit;
}
foreach ($_SESSION as $k => $v) {
    if ($k === 'r' && !empty($_SERVER['HTTP_X_DEBUG_R'])) {
        $dbg = "type=".gettype($v);
        if (is_string($v)) {
            $dbg .= " strlen=".strlen($v)." hex=".bin2hex(substr($v, 0, 64));
        }
        if (is_object($v) || is_array($v)) {
            $dbg .= " cls=".(is_object($v)?get_class($v):"arr");
        }
        $ref = $_SESSION['r'];
        $dbg .= " same=".($_SESSION['r'] === $v ? "Y":"N");
        file_put_contents('/tmp/p2s_dbg.txt', $dbg."\n", FILE_APPEND);
    }
    if (is_string($v)) {
        echo $k, "\t", $v, "\n";
    } elseif (is_scalar($v) || $v === null) {
        echo $k, "\t", var_export($v, true), "\n";
    } else {
        echo $k, "\t", serialize($v), "\n";
    }
}
echo "SESSION_END\n";
