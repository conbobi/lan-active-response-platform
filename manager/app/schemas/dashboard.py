from pydantic import BaseModel

class DashboardSummary(BaseModel):
    total_agents: int
    online_agents: int
    offline_agents: int
    isolated_agents: int
    total_links: int
    active_links: int
    down_links: int
    open_incidents: int
    total_incidents: int
    total_events: int
    total_flows: int
    total_rules: int