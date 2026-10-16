-- SPDX-License-Identifier: Apache-2.0
CREATE TABLE inventory_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1), generation INTEGER NOT NULL CHECK(generation>=1), baseline TEXT NOT NULL CHECK(baseline='unknown'));
INSERT INTO inventory_meta VALUES(1,1,'unknown');
CREATE TABLE owned_artifacts(id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('backup','restore')), location_hint TEXT NOT NULL CHECK(length(location_hint)<=1024), state TEXT NOT NULL CHECK(state='unknown'));
PRAGMA user_version=4;
