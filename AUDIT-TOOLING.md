# Audit tooling provenance

The files `.agents/skills/api-audit/SKILL.md` and
`.agents/skills/owasp-audit/SKILL.md` are third-party development instructions,
not Agent runtime dependencies. Their recorded source and installed hashes are
in `skills-lock.json`.

Source: https://github.com/briiirussell/cybersecurity-skills
License: MIT, Copyright (c) 2026 Bri Russell.
The upstream license was obtained at commit
`c9ade0349f8ecd5c9c68a82a05d2b6012c5fa1d7` during initial publication on 2026-10-14;
this does not assert that installed skill contents match that upstream revision.
License copy: `agent/licenses/cybersecurity-skills-LICENSE`.

Historical E01–E04 manifests remain unchanged. Only repository metadata and
publication documentation were added; the Go module path remains
`serverdeck.local/agent`.
