from langchain_core.messages import AIMessage
from configuration import state
from prompts import firewall_executor_prompt
from .node_utils import POLITO_CLUSTER_KEY, POLITO_URL
from tools import firewall_tools
import logging
from pydantic import BaseModel, Field, ValidationError
from typing import Union, List
import json
from openai import OpenAI

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AddAllowRule(BaseModel):
    """Model for adding an allow rule to the firewall."""
    source_ip: str = Field(..., description="Source IP address")
    dest_ip: str = Field(..., description="Destination IP address")
    protocol: str = Field("tcp", description="Protocol (default: tcp)")

class AddBlockRule(BaseModel):
    """Model for adding a block rule to the firewall."""
    source_ip: str = Field(..., description="Source IP address")
    dest_ip: str = Field(..., description="Destination IP address")
    protocol: str = Field("tcp", description="Protocol (default: tcp)")

class RemoveFirewallRule(BaseModel):
    rule_numbers: List[int] = Field(..., description="List of firewall rule numbers to remove")

class StructuredOutput(BaseModel):
    reasoning: str = Field("", description="Justification about the action to be taken")
    action: List[Union[AddAllowRule, AddBlockRule, RemoveFirewallRule]] = []

ACTION_PRIORITY = {
    RemoveFirewallRule: 0,
    AddAllowRule: 1,
    AddBlockRule: 2
}


async def firewall_executor(state:state.AgentState, config):
    logger.info("Firewall Agent")
    model_name = config.get("configurable", {}).get("model_config", "")
    
    postfix = f"\nRespond with a JSON object matching the following schema (no extra text before or after): {StructuredOutput.model_json_schema()}"
    system_prompt = firewall_executor_prompt.SYSTEM_PROMPT_GPT_OSS
    user_prompt = firewall_executor_prompt.USER_PROMPT_GPT_OSS
    messages = [
        {"role":"system", "content": system_prompt + postfix},
        {"role" : "user", "content" : user_prompt.substitute(
            selected_container=state.selected_container,
            firewall_config=state.firewall_config,
            vulnerable_containers=state.vulnerable_containers
        )}
    ]

    try:
        response = StructuredOutput(reasoning="")
    
        agent = OpenAI(api_key=POLITO_CLUSTER_KEY, base_url=POLITO_URL)
        response_open = agent.chat.completions.create(
            model=model_name,
            temperature=0.3,
            messages=messages # type: ignore
        )
        raw = response_open.choices[0].message.content 

        # logger.info(f"Response: {raw}")
        
        try:
            data = json.loads(raw) # type: ignore
            response = StructuredOutput(**data)
        except (json.JSONDecodeError, ValidationError) as e:
            print("Error parsing or validating output:", e)
            print("Raw output:", raw)
            raise

        message = f"Reasoning:" + str(response.reasoning)
        message += f"\nAction: {str(response.action)}"
        message = AIMessage(content=message)

        return {"messages": [message], "firewall_action": response.action}

    except Exception as e:
        logger.error(f"Error in firewall executor:\n{e}")
    

async def tools_firewall(state: state.AgentState):
    """Execute pending tool calls and update state with enhanced threat data handling"""
    agent_output = state.firewall_action

    agent_output_sorted = sorted(
        agent_output,
        key=lambda action : ACTION_PRIORITY.get(type(action), 99)
    )

    rules_added = []
    rules_removed = []
    new_state = {}
    try:
        if agent_output_sorted:
    
            for action in agent_output_sorted:
                if isinstance(action, AddAllowRule):
                    resp = await firewall_tools.add_allow_rule(
                        source_ip=action.source_ip,
                        dest_ip=action.dest_ip,
                        #port=action.port,
                        protocol=action.protocol
                    )
                    rules_added.append(resp)
                    
                elif isinstance(action, AddBlockRule):
                    resp = await firewall_tools.add_block_rule(
                        source_ip=action.source_ip,
                        dest_ip=action.dest_ip,
                        #port=action.port,
                        protocol=action.protocol
                    )
                    rules_added.append(resp)
                
                elif isinstance(action, RemoveFirewallRule):
                    resp = await firewall_tools.remove_firewall_rule(
                        rule_numbers=action.rule_numbers
                    )
                    rules_removed.append(resp)
            new_state["rules_added_current_epoch"] = rules_added
            new_state["rules_removed_current_epoch"] = rules_removed
    except Exception as e:
        logger.error(f"Exception in tools handling: {e}") 

    return new_state

