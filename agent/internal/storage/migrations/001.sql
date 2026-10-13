-- SPDX-License-Identifier: Apache-2.0
CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,checksum TEXT NOT NULL,release_id TEXT NOT NULL,applied_at INTEGER NOT NULL);
CREATE TABLE identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1),installation_id TEXT NOT NULL CHECK(length(installation_id)=36),security_generation INTEGER NOT NULL CHECK(security_generation>=1),floor_required INTEGER NOT NULL DEFAULT 0 CHECK(floor_required IN (0,1)));
CREATE TABLE settings(singleton INTEGER PRIMARY KEY CHECK(singleton=1),revision INTEGER NOT NULL CHECK(revision>0),document BLOB NOT NULL CHECK(length(document)<=65536));
CREATE TABLE devices(id TEXT PRIMARY KEY,token_hash BLOB,revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)));
CREATE TABLE security_policy(singleton INTEGER PRIMARY KEY CHECK(singleton=1),document BLOB NOT NULL);
CREATE TABLE operations(id TEXT PRIMARY KEY CHECK(length(id)=36 AND substr(id,9,1)='-' AND substr(id,14,1)='-' AND substr(id,15,1)='4' AND substr(id,19,1)='-' AND substr(id,24,1)='-'),actor TEXT NOT NULL,action TEXT NOT NULL,params_hmac BLOB NOT NULL CHECK(length(params_hmac)=32),state TEXT NOT NULL CHECK(state IN ('preparing','running','succeeded','rejected','failed','cancelled','unknown')),phase TEXT NOT NULL,effect TEXT NOT NULL CHECK(effect IN ('none','applied','partial','unknown')),audit_status TEXT NOT NULL,code TEXT NOT NULL,result BLOB NOT NULL CHECK(length(result)<=16384),revision INTEGER NOT NULL CHECK(revision>0),created INTEGER NOT NULL,updated INTEGER NOT NULL,expires INTEGER NOT NULL,bytes INTEGER NOT NULL);
CREATE TABLE object_locks(object_key TEXT PRIMARY KEY,operation_id TEXT NOT NULL REFERENCES operations(id));
CREATE TABLE audit(seq INTEGER PRIMARY KEY AUTOINCREMENT,operation_id TEXT NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,object TEXT NOT NULL,kind TEXT NOT NULL CHECK(kind IN ('intent','result','rejection','gap')),code TEXT NOT NULL,effect TEXT NOT NULL,at INTEGER NOT NULL,bytes INTEGER NOT NULL);
CREATE INDEX audit_time ON audit(at,seq);
CREATE INDEX operations_expiry ON operations(state,expires);
CREATE TABLE operation_changes(seq INTEGER PRIMARY KEY AUTOINCREMENT,operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,revision INTEGER NOT NULL);
CREATE TABLE storage_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),audit_floor INTEGER NOT NULL DEFAULT 0,epoch TEXT NOT NULL);
PRAGMA user_version=1;
