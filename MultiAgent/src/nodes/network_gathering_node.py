from typing import Dict,  Any
from configuration import state
from tools import network_tools, firewall_tools
from tools import summarizer_tool as st
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def network_gathering(state: state.AgentState, config) -> Dict[str, Any]:
    logger.info("Network gathering Node")
    """
    Network Gathering Node:
    Fetch IDS alerts, Docker containers, and firewall rules.
    """
    time_window = config.get("configurable", {}).get("time_window", "0")
    time_window = int(time_window)
    alerts_type = config.get("configurable", {}).get("prompt", "Default")
    memory = config.get("configurable", {}).get("store")
    last_iteration = memory.get_recent_iterations(limit=1)
    last_summary = {}
    last_exposed = {}
    if last_iteration:
        last_summary = last_iteration[0].value.get("security_events_summary", {})
        last_exposed = last_iteration[0].value.get("currently_exposed", {})


    # Call tools directly
    if "fast" in alerts_type:
        alerts_response = await network_tools.get_fast_alerts(time_window=time_window)
    else:
        alerts_response = await network_tools.get_alerts(time_window=time_window)

    containers_response = network_tools.get_docker_containers()
    firewall_response = await firewall_tools.get_firewall_rules()
    
    # Parse results 
    alerts = alerts_response.get('security_events', {})
    
    previous_snapshot = last_summary
     
    vulnerable_containers = containers_response.get('vulnerable_containers', {})
    firewall_config = firewall_response.get('firewall_config', {})
    security_events = st.build_security_summary(
        data=alerts, 
        vulnerable_containers=vulnerable_containers, 
        previous_snapshot=previous_snapshot, 
        last_exposed=last_exposed
        )

    security_events = security_events.get("security_events", {})
    messages = str(f"Security events: {security_events}\n")
    messages += str(f"Vulnerable Containers: {vulnerable_containers}\n")
    messages += str(f"Firewall Configuration: {firewall_config}")
    # Update state
    return {
        "security_events": security_events,
        "vulnerable_containers": vulnerable_containers,
        "firewall_config": firewall_config,
        "messages": messages
    }
