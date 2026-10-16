// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"errors"

	"serverdeck.local/agent/internal/storage"
)

type gapError struct{ details map[string]any }

func (e *gapError) Error() string { return "CURSOR_GAP" }
func (e *gapError) Unwrap() error { return storage.ErrCursor }
func (g *Gateway) eventGap(ctx context.Context, kind, digest string) error {
	if g.eventsDB == nil {
		return storage.ErrStorage
	}
	epoch, floor, latest, err := g.eventsDB.Bounds(ctx)
	if err != nil {
		return err
	}
	cursor, err := g.cursor(kind, epoch, digest, floor)
	if err != nil {
		return err
	}
	tail, err := g.cursor(kind, epoch, digest, latest)
	if err != nil {
		return err
	}
	active := []any{}
	if g.Events != nil {
		active = g.Events.Problems()
	}
	more := len(active) > 100
	if more {
		active = active[:100]
	}
	return &gapError{map[string]any{"earliest_cursor": cursor, "latest_cursor": tail, "active_problems": active, "active_problems_more": more}}
}
func gapDetails(err error) map[string]any {
	var gap *gapError
	if errors.As(err, &gap) {
		return gap.details
	}
	return nil
}
