from langchain_core.messages import AIMessage
from configuration import state
from prompts import exposure_manager_prompt
from .node_utils import OPEN_AI_KEY, POLITO_CLUSTER_KEY, POLITO_URL
from openai import BadRequestError
import logging
from pydantic import BaseModel, ValidationError
import instructor
from openai import OpenAI
from typing import List, Dict, Any
import json
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class StructuredOutput(BaseModel):
    reasoning: str 
    selected_container: dict
    lockdown: bool = False

def _extract_exposure_registry(last_epochs: List[Any]) -> Dict[str, Dict[str, Any]]:
    registry = {}
    for epoch in last_epochs or []:
        data = epoch.value if hasattr(epoch, "value") else epoch
        reg = data.get("exposure_registry")
       
        if reg:
            registry.update(reg)
    return registry



async def exposure_manager(state: state.AgentState, config):
    """
    Decides which container(s) to expose next based on current attack graph
    """
    logger.info("Exploitation Agent")

    episodic_memory = config.get("configurable", {}).get("store")
    model_name = config.get("configurable", {}).get("model_config", "large:4.1")

    last_epochs = episodic_memory.get_recent_iterations(limit=20)
    exposure_registry = _extract_exposure_registry(last_epochs)
    logger.info(f"Exposure registry: {exposure_registry}")
    
    schema = StructuredOutput.model_json_schema()

    logger.info(f"Using: {model_name}")
    message = ""
    try:
        response = StructuredOutput(reasoning="", selected_container={})
        postfix = f"\nRespond with a JSON object matching the following schema (no extra text before or after): {schema}" if "llama" in model_name else ""
        
        messages = [
            {"role":"system", "content": exposure_manager_prompt.SYSTEM_PROMPT + postfix},
            {"role" : "user", "content" : exposure_manager_prompt.USER_PROMPT.substitute(
                vulnerable_containers=state.vulnerable_containers,
                containers_exploitation=state.containers_exploitation,
                exposure_registry=exposure_registry
            )}
        ]

        if '5' in model_name:
            valid_json = False
            while(not valid_json):
                client = OpenAI()
                raw = client.responses.create( 
                    model="gpt-5",
                    temperature=0.3,
                    input=[messages],# type: ignore
                    reasoning={"effort":"low"},
                    
                )
                content = raw.output_text
                try:
                    response = StructuredOutput.model_validate_json(content)
                    valid_json = True
                except ValidationError as e:
                    logger.error(f"Schema validation failed: \n{e}")
                    response = StructuredOutput(reasoning="", selected_container={})
            return
        elif '4.1' in model_name:
            agent = instructor.from_openai(OpenAI(api_key=OPEN_AI_KEY))
            response: StructuredOutput = agent.chat.completions.create(
                model=model_name,
                response_model=StructuredOutput,
                temperature=0.3,
                messages=messages # type: ignore
            )
        
        elif "llama" in model_name:
            agent = OpenAI(api_key=POLITO_CLUSTER_KEY, base_url=POLITO_URL)
            response_open = agent.chat.completions.create(
                model=model_name,
                response_format={
                    "type": "json_schema",
                    "json_schema": {
                        "name": "StructuredOutput",
                        "schema": schema
                    }
                },
                temperature=0.2,
                messages=messages # type: ignore
            )
            raw = response_open.choices[0].message.content 

            logger.info(f"Response: {raw}")
            
            try:
                data = json.loads(raw) # type: ignore
                response = StructuredOutput(**data)
            except (json.JSONDecodeError, ValidationError) as e:
                print("Error parsing or validating output:", e)
                print("Raw output:", raw)
                raise

        
        message += f"Reasoning: {str(response.reasoning)}" + "\n"
        message += f"Selected Container: {str(response.selected_container)}" + "\n"
        message += f"Lockdown: {str(response.lockdown)}"
        message = AIMessage(content=message)
        return {
            "messages": [message],
            "selected_container":response.selected_container,
            "lockdown_status":response.lockdown
            }
    except BadRequestError as e:
        logger.error(f"Error: {e}")
    except Exception as e:
        logger.error(f"Error during json parsing of response in Exposure Manager\n{e}")

    return {
        "messages": [message],
        }
    
