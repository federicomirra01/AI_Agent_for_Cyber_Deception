
import nest_asyncio
from langgraph.graph import START, StateGraph, END
from typing import Literal
import os
import sys
import pickle
from openai import OpenAI
from dotenv import load_dotenv
from nodes import network_gathering_node, graph_and_exploitation_inference_node, exposure_manager_node, firewall_node, save_iteration_node, node_utils
from configuration.state import AgentState
from configuration import memory
nest_asyncio.apply()
import benchmark.benchmark as b

modes = {
    "cons":"consecutive",
    "det":"deterministic",
    "prob": "probabilistic"
}

def is_api_key_valid():
    try:
        client = OpenAI(api_key=node_utils.OPEN_AI_KEY)
        response = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[{"role":"system", "content":"ciao"}],
            )
        print(response.choices[0].message.content)
    except Exception as e:
        print(f"Error: {e}")
        return False
    else:
        return True

def should_continue_from_firewall(state: AgentState) -> Literal["tools_firewall", "persistence_node"]:
    if hasattr(state, 'firewall_action'):
        return "tools_firewall"
    
    return "persistence_node"

def build_graph():
    graph = StateGraph(AgentState)
    
    graph.add_node("network_info_gathering", network_gathering_node.network_gathering)
    graph.add_node("graph_inference", graph_and_exploitation_inference_node.graph_and_exploitation_inference)
    graph.add_node("exposure_manager", exposure_manager_node.exposure_manager)
    graph.add_node("firewall_manager", firewall_node.firewall_executor)
    graph.add_node("persistence_node", save_iteration_node.save_iteration)
    graph.add_node("tools_firewall", firewall_node.tools_firewall)

    # Define execution order
    graph.add_edge(START, "network_info_gathering")
    graph.add_edge("network_info_gathering", "graph_inference") 
    graph.add_edge("graph_inference", "exposure_manager")
    graph.add_edge("exposure_manager", "firewall_manager")
    graph.add_conditional_edges("firewall_manager", should_continue_from_firewall)
    graph.add_edge("tools_firewall", "persistence_node")
    graph.add_edge("persistence_node", END)

    return graph.compile()


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: python3 graph.py <test_name> <mode> <model>")
        sys.exit(1)
    # Get the attacker IP address and container IP address from command line arguments
    test_name = sys.argv[1]
    mode = sys.argv[2]
    model = sys.argv[3]
    if mode not in modes.values():
        print(f"Mode not supported")
        sys.exit(1) 
    print(f"Test arguments:\n{sys.argv}")

    load_dotenv()
    graph = build_graph()

    os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")
    #  Check the validity of the API key    
    api_key_valid = is_api_key_valid()
    print("API key is valid:", api_key_valid)
    modes = {
        "cons":"consecutive",
        "det":"deterministic",
        "prob": "probabilistic"
    }

    episodic_memory = memory.EpisodicMemory()
    dir_name = test_name

    config_dict = {
                "max_epochs": 20,
                "attack_duration": 240,
                "monitor_accumulation_wait": 5,
                "firewall_update_wait": 2,
                "between_epoch_wait": 1,
                "stop_on_lockdown": True,
                "dir_name": dir_name,
                "mode": mode
            }
    runner = b.BenchmarkRunner(config_dict, episodic_memory=episodic_memory)
    initial_state = AgentState(
        messages=[]
    )
    responses = []
    async def my_agent_executor(epoch_num: int):
        response = await graph.ainvoke(initial_state, config={
            "configurable": 
                {
                "store" : episodic_memory, 
                "time_window":2, 
                "prompt":"eve",
                "epoch_num": epoch_num,
                "model_config": f"{model}"
                }
            }
        )
        responses.append(response)
        return response
        

    results = runner.run(my_agent_executor)
    with open(f"./benchmark/benchmark_results/{dir_name}/responses.pkl", "wb") as f:
        pickle.dump(responses, f)


