-- SPDX-License-Identifier: Apache-2.0
CREATE TABLE file_inventory_attestation(singleton INTEGER PRIMARY KEY CHECK(singleton=1), document BLOB NOT NULL CHECK(length(document)<=16000));
CREATE TABLE file_journal(id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('transfer','trash')), owner TEXT NOT NULL, operation_id TEXT NOT NULL, state TEXT NOT NULL, bytes INTEGER NOT NULL CHECK(bytes>=0), created INTEGER NOT NULL, expires INTEGER NOT NULL, document BLOB NOT NULL CHECK(length(document)<=8192));
CREATE INDEX file_journal_state ON file_journal(kind,state);
PRAGMA user_version=5;
