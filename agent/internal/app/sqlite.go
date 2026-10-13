// SPDX-License-Identifier: Apache-2.0
package app

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

// SQLite dependency probe only. E02 creates the actual storage and audit layer.
func sqliteInfo() (string, error) {
	db, e := sql.Open("sqlite3", ":memory:")
	if e != nil {
		return "", e
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var version, source, options string
	e = db.QueryRow("SELECT sqlite_version(), sqlite_source_id()").Scan(&version, &source)
	if e != nil {
		return "", e
	}
	e = db.QueryRow("SELECT group_concat(compile_options, ';') FROM pragma_compile_options").Scan(&options)
	if e != nil {
		return "", e
	}
	return fmt.Sprintf("sqlite_version=%s sqlite_source_id=%s compile_options=%s", version, source, options), nil
}
