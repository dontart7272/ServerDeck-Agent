-- SPDX-License-Identifier: Apache-2.0
CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,checksum TEXT NOT NULL,release_id TEXT NOT NULL,applied_at INTEGER NOT NULL);
CREATE TABLE meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),checksum TEXT NOT NULL,epoch TEXT NOT NULL,revision INTEGER NOT NULL CHECK(revision>0),floor INTEGER NOT NULL,agent_id TEXT NOT NULL CHECK(length(agent_id)=36));
CREATE TABLE records(kind TEXT NOT NULL,id TEXT NOT NULL,series TEXT NOT NULL,segment TEXT NOT NULL,level INTEGER NOT NULL,start INTEGER NOT NULL,stop INTEGER NOT NULL,revision INTEGER NOT NULL CHECK(revision>0),data BLOB NOT NULL CHECK(length(data)<=64000),PRIMARY KEY(kind,id));
CREATE INDEX ranges ON records(kind,series,level,start,id);
CREATE TABLE changes(seq INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT NOT NULL,id TEXT NOT NULL,at INTEGER NOT NULL,data BLOB NOT NULL CHECK(length(data)<=64000));
CREATE UNIQUE INDEX event_ids ON changes(id) WHERE kind='event';
PRAGMA user_version=1;
