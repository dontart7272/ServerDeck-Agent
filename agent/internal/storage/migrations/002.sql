-- SPDX-License-Identifier: Apache-2.0
ALTER TABLE devices ADD COLUMN name TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN created INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN last_seen INTEGER;
ALTER TABLE devices ADD COLUMN revoked_at INTEGER;
ALTER TABLE devices ADD COLUMN revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0);
ALTER TABLE storage_meta ADD COLUMN operation_floor INTEGER NOT NULL DEFAULT 0;
CREATE TABLE auth_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),agent_id TEXT NOT NULL CHECK(length(agent_id)=36));
CREATE TABLE pairing_codes(id TEXT PRIMARY KEY,code_hash BLOB NOT NULL CHECK(length(code_hash)=32),attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0 AND attempts<=5),expires INTEGER NOT NULL,consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0,1)));
UPDATE devices SET revoked=1,token_hash=NULL,revoked_at=0,revision=revision+1;
PRAGMA user_version=2;
