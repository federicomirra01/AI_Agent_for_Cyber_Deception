from typing import List, Dict, Any, Annotated
from langgraph.graph.message import add_messages
from langchain_core.messages import BaseMessage
from dataclasses import field

    
class AgentState:
    # Agents fields
    messages: Annotated[List[BaseMessage], add_messages] = field(default_factory=List)
    
    # Summarize Agent
    security_events: List[Dict] = field(default_factory=List)
    
    # Inference Agent
    inferred_attack_graph: Dict[str, Any] = field(default_factory=Dict)
    selected_container: List[dict] = field(default_factory=List)
    containers_exploitation: Dict[str, Dict[str, Any]] = field(default_factory=Dict) 

    # Firewall Agent
    firewall_action : List[Any] = field(default_factory=List)
    
    # Configuration fields
    firewall_config: List[Dict[str, Any]] = field(default_factory=List)
    vulnerable_containers: List[Dict[str, Any]] = field(default_factory=List)
   
    # Benchmark fields
    rules_added_current_epoch: List[str] = field(default_factory=List)
    rules_removed_current_epoch: List[str] = field(default_factory=List)
    lockdown_status: bool = False
    
    def __init__(self, **kwargs):
        """Custom initializer that can handle both direct field assignment and dictionary unpacking."""
        self.messages = kwargs.get('messages', [])
        
        # Configuration Field
        self.firewall_config = kwargs.get('firewall_config', [])
        self.vulnerable_containers = kwargs.get('vulnerable_containers', [])
    
        # Summarize Agent Field
        self.security_events = kwargs.get('security_events', [])
    
        # Inference Agent Field
        self.containers_exploitation = kwargs.get('containers_exploitation', {})
        self.inferred_attack_graph = kwargs.get('inferred_attack_graph', {})
    
        # Exploitation Agent Field
        self.selected_container = kwargs.get('selected_container', [])
        self.lockdown_status = kwargs.get('lockdown_status', False)
   
        #Firewall Agent Field
        self.firewall_action = kwargs.get('firewall_action', [])
   
        # Benchmark Fields 
        self.rules_added_current_epoch = kwargs.get('rules_added_current_epoch', [])
        self.rules_removed_current_epoch = kwargs.get('rules_removed_current_epoch', [])
        
        
    
