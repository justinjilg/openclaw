# BrainstormRouter Stress Test Skill

Exercises the BrainstormRouter API across all configured providers to validate routing, rate limiting, budget enforcement, failover, and Thompson sampling behavior.

## Commands

| Command | Description | Used by |
|---------|-------------|---------|
| `br-stress-burst` | Fire rapid concurrent requests to test rate limiting (60 RPM) | main, ops |
| `br-stress-sweep` | Sequential requests across all providers to validate routing | main, ops |
| `br-stress-budget` | Sustained low-cost requests to test budget tracking accuracy | main, ops |
| `br-stress-failover` | Request known-bad models to test error handling and recovery hints | main, ops |
| `br-stress-report` | Aggregate results from prior runs into a structured report | ops |

## Authentication

All scripts use `$BRAINSTORMROUTER_API_KEY` from the environment (injected by start.sh from 1Password).

## Safety

- All commands are READ-ONLY at the infrastructure level — they call chat/completions but do not modify BR config
- Each test uses minimal tokens (max_tokens: 10-50) to limit cost
- Burst test respects a configurable concurrency cap (default: 10)
- Budget test has a hard cost ceiling ($0.50 per run)
- Results written to workspace only (br-stress-results/)
- No credentials are logged or written to output files
