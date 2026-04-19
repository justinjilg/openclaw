# HEARTBEAT.md - Proactive Checks

## Event Sources to Monitor

### GitHub (justinjilg)
- [ ] New PRs requiring review
- [ ] Failed CI/CD runs
- [ ] Security alerts
- [ ] New issues assigned

### BrainstormRouter
- [ ] Budget approaching limit (>80%)
- [ ] Error rate spikes
- [ ] Circuit breaker activations
- [ ] Kill switch events

### OpenClaw
- [ ] Gateway health status
- [ ] Budget consumption
- [ ] Error logs

### Workspace
- [ ] Uncommitted changes
- [ ] Large files added
- [ ] Security-sensitive files modified

## Smart Notification Rules

| Condition | Urgency | Action |
|-----------|---------|--------|
| BR kill switch active | CRITICAL | Immediate alert |
| Budget >90% | HIGH | Alert + suggest optimization |
| GitHub PR >24h old | MEDIUM | Daily digest |
| Uncommitted changes | LOW | Weekly summary |
| New model available | INFO | Weekly summary |

## Proactive Value Opportunities

- "I noticed BR errors spiked — investigating"
- "GitHub PR #123 has been open 2 days — shall I review?"
- "Budget at 85% — here are 3 ways to optimize"
- "Pattern detected: X often precedes Y — heads up"

## Current Status

- [x] Skills system implemented
- [ ] Event router (pending)
- [ ] GitHub webhook handler (pending)
- [ ] BR alert handler (pending)
- [ ] Smart notification (pending)
