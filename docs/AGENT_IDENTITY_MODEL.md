# Agent Identity Model

- An agent is an `ActorId` inside an `OrgId`, with an `AuthStrength`.
- Agents are first-class in audit: every journaled decision/action names its agent.
- Agent keys rotate; rotation is an administrative action (journaled).
- Hermes/OpenClaw agent identities map 1:1 onto Enterprise actors; Research
  Lab identities are never valid at the Enterprise gateway.
