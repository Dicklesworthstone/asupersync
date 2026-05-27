# CLAUDE.md — asupersync

> Agent-specific instructions for Claude working in the asupersync codebase.

---

## Primary Directive

**All coding guidelines, rules, and conventions are documented in [`AGENTS.md`](./AGENTS.md).**

This file serves as the entry point for Claude-specific instructions, but the comprehensive agent guidelines are maintained in `AGENTS.md` to ensure consistency across all AI coding agents working in this codebase.

## Quick Reference

For immediate reference, the most critical rules from AGENTS.md are:

1. **NO FILE DELETION** without express permission
2. **Use `main` branch only** — never `master`, never create branches
3. **NO `#![deny(unsafe_code)]` violations** — unsafe requires explicit `#[allow(unsafe_code)]`
4. **Follow the session protocol** — `br sync --flush-only`, commit changes, `git push`

## Full Guidelines

**👉 See [`AGENTS.md`](./AGENTS.md) for complete instructions.**

The AGENTS.md file contains:
- Fundamental rules and overrides
- Git workflow requirements  
- Rust coding standards
- Testing and quality requirements
- Session protocols
- Lock ordering and concurrency guidelines
- Bead management procedures

---

*This delegation structure ensures all agents follow identical guidelines while maintaining Claude-specific entry point for tooling compatibility.*