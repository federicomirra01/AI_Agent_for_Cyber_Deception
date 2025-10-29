from configuration import state
import logging
import os
from dotenv import load_dotenv
from typing import Dict, List, Any, Tuple
from pydantic import BaseModel, Field
import ipaddress
import copy
# Load environment variables
load_dotenv()
OPEN_AI_KEY = os.getenv("OPENAI_API_KEY")
POLITO_CLUSTER_KEY = os.getenv("POLITO_CLUSTER_KEY")

DEEPSEEK_STRING = "openai/gpt-oss-20b:free" 
MISTRAL_STRING = "mistralai/Mistral-7B-Instruct-v0.1"
POLITO_URL = "https://kubernetes.polito.it/vllm/v1"
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_memory_context(state: state.AgentState, episodic_memory):
    """Load memory context from episodic memory and update state"""
    
    recent_iterations = episodic_memory.get_recent_iterations(limit=10)
    if not recent_iterations:
        return []
    
    logger.info(f"Loaded {len(recent_iterations)} recent iterations from episodic memory.")
    return recent_iterations

class PhaseDelta(BaseModel):
    phase: str
    evidence_quotes: List[str]

class EdgeUpdate(BaseModel):
    from_: str = Field(..., alias="from")
    to: str
    new_phases: List[PhaseDelta]

class ContainersExploitationUpdate(BaseModel):
    ip: str
    service: str
    level_prev: int
    level_new: int
    evidence_quotes: List[str]

class DeltaOutput(BaseModel):
    reasoning: str
    edge_updates: List[EdgeUpdate] = []

PHASE_RANK = {
  "scan":0,
  "initial-access/rce":1,
  "data-exfil-user":2,
  "privilege-escalation":3,
  "data-exfil-root":4
}

EXPLOITATION_FROM_PHASE = {
  "scan": 25,
  "initial-access/rce": 50,
  "data-exfil-user": 75,
  "privilege-escalation": 100,
  "data-exfil-root": 100
}

def ip_in_subnet(ip: str, subnet: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet)
    except Exception:
        return False

def find_edge(edges: List[Dict[str,Any]], attacker: str, container: str) -> Tuple[int, Dict[str,Any] | None]:
    for i, e in enumerate(edges):
        if e.get("from") == attacker and e.get("to") == container:
            return i, e
    return -1, None

def validate_phase_name(phase: str) -> bool:
    return phase in PHASE_RANK

def merge_deltas_into_graph(prev_graph: Dict[str,Any],
                            prev_exploitation: List[Dict[str,Any]],
                            vulnerable_containers: List[Dict[str,Any]],
                            deltas: DeltaOutput,
                            ) -> Dict[str,Any]:
    # deep copy to avoid mutating inputs on failure
    graph = copy.deepcopy(prev_graph)
    edges = graph.get("edges", [])
    interesting = { (n["ip"], n["service"]) for n in graph.get("interesting", []) }

    # Build quick lookup for container config and exploitation
    containers_services = { vc["ip"]: vc["service"] for vc in vulnerable_containers }
    exploit_map = { pe["ip"]: copy.deepcopy(pe) for pe in prev_exploitation }  # keyed by ip

    # If no deltas -> return prev unchanged
    if not deltas.edge_updates:
        rolled = []
    # Build quick lookup for container config (you already have vulnerable_containers)
        containers_services = { vc["ip"]: vc["service"] for vc in vulnerable_containers }
        for pe in prev_exploitation:
            ip = pe["ip"]
            service = pe.get("service", containers_services.get(ip))
            # roll level_prev forward to last level_new
            level_prev = pe.get("level_new", pe.get("level_prev", 0))
            rolled.append({
                "ip": ip,
                "service": service,
                "level_prev": level_prev,
                "level_new": level_prev,
                "changed": False,
                "evidence_quotes": []
            })

        return {
            "inferred_attack_graph": prev_graph,
            "containers_exploitation": rolled
        }

    # 1) Apply edge updates
    for eu in deltas.edge_updates:
        att = eu.from_
        vc = eu.to
        # SERVICE & IP GUARDS
        if not ip_in_subnet(att, "192.168.100.0/24"):
            raise ValueError(f"attacker {att} outside attacker subnet")
        if not ip_in_subnet(vc, "172.20.0.0/24"):
            raise ValueError(f"container {vc} outside containers subnet")
        if vc not in containers_services:
            raise ValueError(f"container {vc} not in vulnerable_containers")

        idx, existing_edge = find_edge(edges, att, vc)
        created_new_edge = False
        if existing_edge is None:
            # create new edge skeleton
            created_new_edge = True
            existing_edge = {
                "from": att,
                "to": vc,
                "phases": [],
                "current_phase": None,
                "vector": None
            }
            edges.append(existing_edge)
            idx = len(edges) - 1
        
        added_phases = []
        for pd in eu.new_phases:
            if not validate_phase_name(pd.phase):
                raise ValueError(f"unknown phase {pd.phase}")
            # Check evidence quotes exist
            if not pd.evidence_quotes or any(not q or not isinstance(q, str) for q in pd.evidence_quotes):
                raise ValueError("each added phase must include >=1 exact evidence_quotes")
            # If phase already present on edge, skip
            already = False
            for existing_phase in existing_edge["phases"]:
                if existing_phase["phase"] == pd.phase:
                    already = True
                    break
            if already:
                continue
            # Add phase object
            phase_obj = {
                "phase": pd.phase,
                "evidence_quotes": pd.evidence_quotes,
            }
            existing_edge["phases"].append(phase_obj)
            added_phases.append(pd.phase)

        if added_phases:
            # Sort/normalize phases by rank for predictable output
            existing_edge["phases"].sort(key=lambda p: PHASE_RANK.get(p["phase"], 0))
            # update current_phase / vector to the highest rank
            highest = max(existing_edge["phases"], key=lambda p: PHASE_RANK[p["phase"]])
            existing_edge["current_phase"] = highest["phase"]
            existing_edge["vector"] = highest["phase"]
            
    # 2) Recompute exploitation per container deterministically as MAX over edges
    # Build per-container edge list
    per_vc_edges = {}
    for e in edges:
        per_vc_edges.setdefault(e["to"], []).append(e)

    containers_updates_result = []
    for vc_ip, service in containers_services.items():
        prev_entry = exploit_map.get(vc_ip, {"ip": vc_ip, "service": service, "level_prev": 0, "level_new": 0, "changed": False, "evidence_quotes": []})
        level_prev = prev_entry.get("level_new", prev_entry.get("level_prev", 0))

        # compute max over edges
        max_level = level_prev
        evidence_for_level = []
        for e in per_vc_edges.get(vc_ip, []):
            # highest phase of edge -> its exploitation mapping
            if not e.get("phases"):
                continue
            highest_phase = max(e["phases"], key=lambda p: PHASE_RANK[p["phase"]])
            lvl = EXPLOITATION_FROM_PHASE.get(highest_phase["phase"], 0)
            if lvl > max_level:
                max_level = lvl
                # minimal evidence: take the quote from the newly added phase(s) if present; fallback to highest_phase quote
                evidence_for_level = highest_phase.get("evidence_quotes", [])[:1]
        # enforce monotonicity
        if max_level < level_prev:
            max_level = level_prev

        changed = (max_level != level_prev)
        if changed:
            # If level_new >=66 -> ensure container in interesting set
            if max_level >= 66:
                interesting.add((vc_ip, service))
            containers_updates_result.append({
                "ip": vc_ip,
                "service": service,
                "level_prev": level_prev,
                "level_new": max_level,
                "evidence_quotes": evidence_for_level
            })

    # Build full, rolled-forward state for all containers
    full_state = []
    for vc_ip, service in containers_services.items():
        # start from previous baseline (take prev level from the previous epoch, if present)
        prev_entry = exploit_map.get(vc_ip, {
            "ip": vc_ip, "service": service,
            "level_prev": 0, "level_new": 0,
            "changed": False, "evidence_quotes": []
        })

        # previous level must reflect the previous epoch's final level (if available)
        level_prev = prev_entry.get("level_new", prev_entry.get("level_prev", 0))

        # determine proposed new level as max over edges (do not reduce below previous)
        level_new = level_prev
        for e in per_vc_edges.get(vc_ip, []):
            if e.get("phases"):
                highest_phase = max(e["phases"], key=lambda p: PHASE_RANK[p["phase"]])
                lvl = EXPLOITATION_FROM_PHASE.get(highest_phase["phase"], 0)
                if lvl > level_new:
                    level_new = lvl

        # enforce monotonicity (should already hold, but be explicit)
        if level_new <= level_prev:
            level_new = level_prev

        changed = (level_new != level_prev)

        # try to attach evidence if we recorded an update for this container earlier
        evidence = []
        for upd in containers_updates_result:
            if upd["ip"] == vc_ip:
                evidence = upd.get("evidence_quotes", [])
                break

        full_state.append({
            "ip": vc_ip,
            "service": service,
            "level_prev": level_prev,
            "level_new": level_new,
            "changed": changed,
            "evidence_quotes": evidence
        })


    # Update graph object fields and interesting list
    graph["edges"] = edges
    graph["interesting"] = [{"ip": ip, "service": svc} for ip, svc in sorted(list(interesting))]
    # final output
    return {
        "inferred_attack_graph": graph,
        "containers_exploitation": full_state
    }

def _normalized_quote(q: str) -> str:
    # normalize for dedupe: case-insensitive, trim, normalize CRLF
    return (q or "").replace("\r\n", "\n").strip().lower()

def _phase_order_key(phase_name: str) -> int:
    return PHASE_RANK.get(phase_name, 999)

def _existing_phases_for_edge(prev_graph: Dict[str, Any], att: str, dst: str) -> set[str]:
    for e in prev_graph.get("edges", []):
        if e.get("from") == att and e.get("to") == dst:
            return {p.get("phase") for p in e.get("phases", [])}
    return set()

def _ensure_prefix_inferred(quote: str) -> str:
    prefix = "inferred from later phase: "
    # avoid double-prefix if LLM already prefixed
    if quote.startswith(prefix):
        return quote
    return f"{prefix}{quote}"

def enforce_backfill_on_deltas(
    deltas: DeltaOutput,
    prev_graph: Dict[str, Any]
) -> DeltaOutput:
    """
    Deterministically enforce mandatory backfill for each edge_update:
    - For every emitted phase P, ensure all lower-ranked phases exist either
      in prev_graph OR are added now (as inferred) BEFORE P.
    - Use P's first evidence quote as the reused substring for inferred phases,
      prefixed with 'inferred from later phase: ...'.
    - Sort new_phases by taxonomy order and dedupe within this epoch.
    - Sort edge_updates by (to asc, from asc).
    """
    if not deltas or not deltas.edge_updates:
        return deltas  # nothing to do

    fixed_edge_updates: List[EdgeUpdate] = []

    for eu in deltas.edge_updates:
        # Get existing (previous) phases for this edge from prior graph
        prev_present = _existing_phases_for_edge(prev_graph, eu.from_, eu.to)

        # Work on a local list (copy)
        original_new = list(eu.new_phases or [])
        # Sort original phases to process from lowest to highest
        original_new.sort(key=lambda pd: _phase_order_key(pd.phase))

        # We will accumulate in 'patched'
        patched: List[PhaseDelta] = []
        # Keep fast-check sets for presence & dedupe
        phases_already_emitted = set()  # phase names in this emission
        quote_seen = set()  # (phase, normalized_quote)

        # seed with nothing; we will add inferred phases on the fly
        for pd in original_new:
            phase_name = pd.phase
            if not validate_phase_name(phase_name):
                # Unknown phase names are rejected later in merge; keep as-is to preserve behavior
                pass

            # Determine missing lower-ranked predecessors
            rank = _phase_order_key(phase_name)
            lower_needed = [p for p, r in PHASE_RANK.items() if r < rank and p != "data-exfil-user"]
            # Insert missing lower phases (not present previously and not already emitted now)
            # Choose base quote from this phase's first evidence (must exist per schema)
            base_quote = (pd.evidence_quotes[0] if pd.evidence_quotes else "").replace("\r\n", "\n")
            for lp in sorted(lower_needed, key=_phase_order_key):
                if lp not in prev_present and lp not in phases_already_emitted:
                    inferred_quote = _ensure_prefix_inferred(base_quote) if base_quote else _ensure_prefix_inferred("")
                    norm_key = (lp, _normalized_quote(inferred_quote))
                    if norm_key not in quote_seen:
                        patched.append(PhaseDelta(phase=lp, evidence_quotes=[inferred_quote]))
                        phases_already_emitted.add(lp)
                        quote_seen.add(norm_key)

            # Now add the actual phase P
            # Dedupe by (phase, normalized_quote). If multiple quotes, keep them but dedupe each by normalized form.
            if pd.evidence_quotes:
                # Keep original quotes but ensure uniqueness per phase
                dedup_quotes = []
                phase_quote_seen = set()
                for q in pd.evidence_quotes:
                    qn = _normalized_quote(q.replace("\r\n", "\n"))
                    if qn not in phase_quote_seen:
                        dedup_quotes.append(q)
                        phase_quote_seen.add(qn)
                normalized_first = _normalized_quote(dedup_quotes[0])
                norm_key = (phase_name, normalized_first)
                if norm_key not in quote_seen:
                    patched.append(PhaseDelta(phase=phase_name, evidence_quotes=dedup_quotes))
                    phases_already_emitted.add(phase_name)
                    quote_seen.add(norm_key)
            else:
                # Schema requires >=1 evidence; if missing, we still insert a placeholder using base_quote
                inferred_quote = base_quote or ""
                if inferred_quote:
                    norm_key = (phase_name, _normalized_quote(inferred_quote))
                    if norm_key not in quote_seen:
                        patched.append(PhaseDelta(phase=phase_name, evidence_quotes=[inferred_quote]))
                        phases_already_emitted.add(phase_name)
                        quote_seen.add(norm_key)
                else:
                    # As a last resort, keep an empty quote to avoid crashing, merge will reject if invalid
                    patched.append(PhaseDelta(phase=phase_name, evidence_quotes=[""]))

        # Final ordering by taxonomy rank
        patched.sort(key=lambda x: _phase_order_key(x.phase))

        # Build a new EdgeUpdate with patched phases
        fixed_edge_updates.append(
            EdgeUpdate(**{"from": eu.from_, "to": eu.to, "new_phases": patched})
        )

    # Sort edge_updates by (to asc, from asc) for determinism
    fixed_edge_updates.sort(key=lambda e: (e.to, e.from_))

    # Return a NEW DeltaOutput with same reasoning but patched edge_updates
    return DeltaOutput(reasoning=deltas.reasoning, edge_updates=fixed_edge_updates)


def get_last_epoch_fields(last_epoch):
    last_exploitation = []
    last_attack_graph = {}
    if last_epoch:
        last_epoch = last_epoch[0].value
        last_exploitation = last_epoch.get('containers_exploitation', [])
        last_attack_graph = last_epoch.get('inferred_attack_graph', {})

    return last_exploitation, last_attack_graph
