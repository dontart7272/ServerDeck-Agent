-- SPDX-License-Identifier: Apache-2.0
CREATE TABLE rules(id TEXT PRIMARY KEY,revision INTEGER NOT NULL CHECK(revision>0),document BLOB NOT NULL CHECK(length(document)<=4096));
CREATE TABLE rule_versions(singleton INTEGER PRIMARY KEY CHECK(singleton=1),next_revision INTEGER NOT NULL CHECK(next_revision>0),epoch TEXT NOT NULL);
INSERT INTO rule_versions VALUES(1,2,'');
PRAGMA user_version=3;
