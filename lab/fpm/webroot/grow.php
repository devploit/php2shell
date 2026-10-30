<?php
/* php2shell FPM laboratory — the single-surface arm endpoint.
 *
 * Two ways to make a stock pool arm the producer state, in the order the
 * client tries them:
 *
 * 1. AMPLIFIER (primary): POST p=<session-format payload>.  The payload is
 *    four short strings (the leak's R:2 hook reads data[1] out of the stale
 *    var_hash) followed by a wide array of nested sub-arrays whose decode
 *    multiplies memory ~22x per payload byte while
 *    BG(unserialize).level == 1 - so the OOM lands inside unserialize()
 *    from a single request, with no session file, no save, and no
 *    memory_limit split.  Needs the front to pass ~5 MB bodies.
 * 2. GROWTH (fallback): POST k/v appends to the session in small chunks
 *    until the save wall is close enough for the probe/amplifier to cross.
 *
 * GROW_OK is printed *after* session_start()/session_decode(): a decode
 * OOM fatals before the marker, which is how the client detects the arm
 * over HTTP.  B=<n> reports the body bytes that actually arrived (a body
 * over post_max_size is discarded silently), and the number is the
 * payload currently in the session.
 *
 * Stand-in for application operations that store request data in the
 * session under an attacker-influenced key (carts, wishlists, wizard
 * steps) or decode attacker-controlled session data.  Lab-only scaffold.
 */
session_start();
/* lab debug: the save runs at RSHUTDOWN inside zend_try, so an encode OOM
 * is swallowed silently - force it into a log we can read. */
ini_set('log_errors', '1');
ini_set('error_log', '/tmp/p2s_grow_err.log');
if (isset($_POST['p']) && $_POST['p'] !== '') {
    /* Decode-side amplifier (the primary arm): a few short strings first
     * (so the stale var_hash carries them at data[0..3] for the leak),
     * then a wide array of nested sub-arrays that costs ~28 payload bytes
     * per ~620 bytes of live HashTables.  It decodes with
     * BG(unserialize).level == 1, so the OOM lands INSIDE unserialize,
     * which is exactly the producer arm: nothing is saved, nothing needs a
     * big session file, and the save-side wall never comes into play. */
    $p2s_rc = session_decode((string) $_POST['p']);
} else {
    $p2s_rc = null;
}
if (isset($_POST['k'], $_POST['v'])) {
    $k = preg_replace('/[^A-Za-z0-9,_-]/', '', (string) $_POST['k']);
    if ($k !== '') {
        $chunk = substr((string) $_POST['v'], 0, 1 << 20);
        $prev = isset($_SESSION[$k]) && is_string($_SESSION[$k]) ? $_SESSION[$k] : '';
        $_SESSION[$k] = $prev . $chunk;
    }
}
$size = 0;
foreach ($_SESSION as $value) {
    if (is_string($value)) {
        $size += strlen($value);
    }
}
/* body=<len> lets the probe verify its body actually arrived: a body over
 * post_max_size is discarded silently (no 413), which would otherwise make
 * the probe look harmless when it never allocated anything. */
$inlen = '';
if (isset($_POST['x']) && is_string($_POST['x'])) {
    $inlen = strlen($_POST['x']);
} elseif (isset($_POST['p']) && is_string($_POST['p'])) {
    $inlen = strlen($_POST['p']);
}
$kk = '-';
if (isset($_SESSION['k'])) {
    $kk = is_array($_SESSION['k']) ? ('A' . count($_SESSION['k'])) : 'S';
}
$rc = $p2s_rc === null ? '-' : ($p2s_rc ? '1' : '0');
echo "GROW_OK ", $size, " B", $inlen, " K", $kk, " RC", $rc,
     " U", memory_get_usage(true),
     " P", memory_get_peak_usage(true),
     " UL", memory_get_usage(false),
     " PL", memory_get_peak_usage(false), "\n";
