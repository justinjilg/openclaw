# BrainstormRouter Operations Skill

Provides shell-callable wrappers around the BrainstormRouter API for monitoring and management.

## Commands

| Command | Description | Used by |
|---------|-------------|---------|
| `br-health` | Check BR API health and latency | ops |
| `br-usage` | Get per-agent usage and budget consumption | ops |
| `br-agents` | List all registered agents and their status | ops |

## Authentication

All scripts use `$BRAINSTORMROUTER_API_KEY` from the environment (injected by start.sh from 1Password).

## Safety

- All commands are READ-ONLY — they query the API but never modify state
- No credentials are logged or written to output files
- Scripts exit with non-zero status on API errors
