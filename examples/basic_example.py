"""
Agent-Governance-Kit - Core Example
Demonstrates basic Agent-Governance-Kit functionality for agent policy enforcement.
"""

from agent_governance_kit import GovernanceEngine, Policy, AgentRegistry

def main():
    # Initialize the governance engine
    engine = GovernanceEngine(name="production-governance")

    # Define policies
    policy = Policy(
        name="data-access",
        rules=[
            {"action": "read", "resource": "public/*", "effect": "allow"},
            {"action": "write", "resource": "private/*", "effect": "deny"},
            {"action": "execute", "resource": "tools/*", "effect": "allow", "conditions": {"rate_limit": 100}}
        ]
    )
    engine.add_policy(policy)

    # Register agents
    registry = AgentRegistry(engine)
    registry.register("data-agent", policies=["data-access"])

    # Check authorization
    allowed = engine.authorize(
        agent="data-agent",
        action="read",
        resource="public/data.csv"
    )

    print(f"Governance: {engine.name}")
    print(f"Active policies: {engine.policy_count}")
    print(f"Authorization check: {allowed}")

if __name__ == "__main__":
    main()
