# Heartbeat Task

Run the following checks and write results to a daily report file.

## Core Health Checks (every heartbeat)

1. Execute `br_get_health` MCP tool — record API health status and latency
2. Execute `br_get_usage` MCP tool — record per-agent budget consumption
3. Execute `br_list_agents` MCP tool — verify all 5 agents are registered and active
4. Write report to `daily-report-YYYY-MM-DD.md` (append if file exists for today)
5. If any agent budget >80% consumed OR API unhealthy, escalate to `main` via `sessions_send`

## Governance Checks (every heartbeat)

6. Execute `br_agent_anomaly` MCP tool — check for anomaly scores across all agents
7. Execute `br_get_behavioral_profiles` MCP tool — check for behavioral drift
8. Execute `br_get_cost_forecast` MCP tool — check if projected spend exceeds daily limits
9. Execute `br_get_insights` MCP tool — record model performance and routing decisions
10. Execute `br_get_leaderboard` MCP tool — track model performance rankings

## Dashboard Reporting (every heartbeat)

11. Write structured JSON to `dashboard-data.json` with all collected metrics:
    - Health status, latency, uptime
    - Per-agent budget usage (used, limit, percentage)
    - Anomaly scores per agent
    - Model leaderboard (top 5 models by performance)
    - Cost forecast (projected daily/monthly spend)
    - Timestamp of last update

## Escalation Criteria

Escalate to `main` immediately if:
- BR API is unhealthy or unreachable
- Any agent has consumed >80% of daily budget
- Error rate exceeds 5% in the last hour
- Anomaly score for any agent exceeds threshold
- Behavioral profile shows significant drift
- Cost forecast projects >120% of daily budget
- Any agent has been running for >2 hours continuously
