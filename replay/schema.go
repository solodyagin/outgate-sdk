package replay

const schema = `
CREATE TABLE replay_metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL CHECK (version = 1),
    namespace TEXT NOT NULL,
    epoch BLOB NOT NULL CHECK (length(epoch) = 32),
    clock_ns INTEGER NOT NULL DEFAULT 0 CHECK (clock_ns >= 0),
    used INTEGER NOT NULL DEFAULT 0 CHECK (used >= 0)
) STRICT;

CREATE TABLE replay_callers (
    caller TEXT PRIMARY KEY,
    used INTEGER NOT NULL CHECK (used >= 0)
) STRICT;

CREATE TABLE replay_nonces (
    leg TEXT NOT NULL,
    caller TEXT NOT NULL,
    key_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    retain_until INTEGER NOT NULL,
    PRIMARY KEY (leg, caller, key_id, nonce)
) STRICT;

CREATE INDEX replay_expiration ON replay_nonces (retain_until);

CREATE TRIGGER replay_insert AFTER INSERT ON replay_nonces BEGIN
    UPDATE replay_metadata SET used = used + 1 WHERE id = 1;
    INSERT INTO replay_callers (caller, used) VALUES (new.caller, 1)
        ON CONFLICT(caller) DO UPDATE SET used = used + 1;
END;

CREATE TRIGGER replay_delete AFTER DELETE ON replay_nonces BEGIN
    UPDATE replay_metadata SET used = used - 1 WHERE id = 1;
    UPDATE replay_callers SET used = used - 1 WHERE caller = old.caller;
    DELETE FROM replay_callers WHERE caller = old.caller AND used = 0;
END;
`

const countersConsistent = `
WITH counts AS (SELECT caller, count(*) AS used FROM replay_nonces GROUP BY caller)
SELECT (SELECT used FROM replay_metadata WHERE id = 1) = (SELECT count(*) FROM replay_nonces)
    AND (SELECT count(*) FROM sqlite_schema WHERE type='trigger' AND tbl_name='replay_nonces'
        AND name IN ('replay_insert','replay_delete')) = 2
    AND NOT EXISTS (
        SELECT 1 FROM counts FULL OUTER JOIN replay_callers AS c USING (caller)
        WHERE counts.used IS NOT c.used
    )`

const pruneExpired = `
DELETE FROM replay_nonces WHERE rowid IN (
    SELECT rowid FROM replay_nonces WHERE retain_until < ? ORDER BY retain_until LIMIT 256
)`
