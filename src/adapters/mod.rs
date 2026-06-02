//! Adapter registries — pluggable per-category contracts so a new
//! integration point (a host, an IdP, a plugin) is a one-file change
//! instead of a five-file edit.
//!
//! Paul's direction in #92: *"It should be easy for an agent to write
//! an adapter and wire it up to wireup. Minimal boilerplate, a clear
//! contract, a template, and tests — author one, register it, done."*
//!
//! ## Categories
//!
//! - [`harness`] — Host adapters (Claude Code, Cursor, Claude Desktop,
//!   VS Code Insiders, GitHub Copilot CLI, Pi, OpenCode, …). Each
//!   declares its probable MCP-config file paths + the JSON shape its
//!   host expects. Consumed by `cli::cmd_setup`.
//!
//! Future categories (per #92, deferred to dedicated PRs since they
//! need cross-fleet coordination):
//! - SSO / IdP provider adapters (Google Workspace, Okta, Azure AD, …)
//! - Plugin / extension adapters (wire-plugin marketplace, A2A bridge,
//!   `did:wire` method)

pub mod harness;
