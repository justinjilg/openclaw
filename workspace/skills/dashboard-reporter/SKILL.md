# Dashboard Reporter Skill

Writes structured JSON data for the BR-integrated dashboard.

## Usage

Called by the `ops` agent on each heartbeat cycle, after all health/usage/governance checks are complete.

## Output

Writes `dashboard-data.json` to the ops workspace with the following structure:

```json
{
  "timestamp": "ISO-8601",
  "health": { "status": "healthy|degraded|down", "latencyMs": 0, "uptime": "" },
  "agents": [
    { "id": "", "status": "", "budgetUsed": 0, "budgetLimit": 0, "budgetPct": 0, "anomalyScore": 0 }
  ],
  "models": {
    "leaderboard": [{ "id": "", "provider": "", "score": 0, "requestCount": 0 }]
  },
  "costs": {
    "todayUsed": 0, "todayLimit": 14.50, "todayPct": 0,
    "forecastDaily": 0, "forecastMonthly": 0
  },
  "alerts": []
}
```

## Instructions for ops agent

After collecting all metrics from MCP tools, construct the JSON object above and write it to `dashboard-data.json` in your workspace. The custom BR dashboard reads this file to display live metrics.
