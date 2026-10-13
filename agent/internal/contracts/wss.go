// SPDX-License-Identifier: Apache-2.0
package contracts

// This is stateless message validation only. Session ownership, cumulative
// subscription quota, pending ack and token revocation belong to the transport.
func validateWssClient(m map[string]any) error {
	if m["type"] != "subscribe" {
		return nil
	}
	seen := map[string]bool{}
	for _, value := range m["subscriptions"].([]any) {
		sub := value.(map[string]any)
		id := sub["id"].(string)
		if seen[id] {
			return ErrInvalid
		}
		seen[id] = true
		// Reuse temporal semantics of the corresponding named read.
		if sub["topic"] == "events" {
			p := sub["params"].(map[string]any)
			if e := validateTimeRange(p); e != nil {
				return e
			}
		}
	}
	return nil
}
