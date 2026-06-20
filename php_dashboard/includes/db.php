<?php
require_once __DIR__ . '/config.php';

function get_db(): SQLite3 {
    static $db = null;
    if ($db === null) {
        $db = new SQLite3(DB_PATH, SQLITE3_OPEN_READWRITE);
        $db->busyTimeout(5000);
        // WAL mode and busy timeout set here; WAL journal mode set by init_db.py
    }
    return $db;
}

function qdb(string $sql, array $params = []): array {
    try {
        $db   = get_db();
        $stmt = $db->prepare($sql);
        if ($stmt === false) return [];
        foreach ($params as $i => $v) {
            if ($v === null) {
                $stmt->bindValue($i + 1, null, SQLITE3_NULL);
            } else {
                $type = is_int($v) ? SQLITE3_INTEGER : (is_float($v) ? SQLITE3_FLOAT : SQLITE3_TEXT);
                $stmt->bindValue($i + 1, $v, $type);
            }
        }
        $res = $stmt->execute();
        if ($res === false) return [];
        $rows = [];
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
            $rows[] = $row;
        }
        return $rows;
    } catch (Exception $e) {
        error_log('[IIDS DB] qdb error: ' . $e->getMessage());
        return [];
    }
}

function wdb(string $sql, array $params = []): bool {
    try {
        $db   = get_db();
        $stmt = $db->prepare($sql);
        if ($stmt === false) return false;
        foreach ($params as $i => $v) {
            if ($v === null) {
                $stmt->bindValue($i + 1, null, SQLITE3_NULL);
            } else {
                $type = is_int($v) ? SQLITE3_INTEGER : (is_float($v) ? SQLITE3_FLOAT : SQLITE3_TEXT);
                $stmt->bindValue($i + 1, $v, $type);
            }
        }
        $stmt->execute();
        return true;
    } catch (Exception $e) {
        error_log('[IIDS DB] wdb error: ' . $e->getMessage());
        return false;
    }
}

/** Return last inserted row ID */
function wdb_id(): int {
    return (int)get_db()->lastInsertRowID();
}
