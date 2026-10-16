"""The shared guardrail chain every blueprint is wired into — parity by construction.

    START -> policy -> prompt_defense -> agent_control_prompt -> nemo_input_rails
          -> scheduling_intake -> <core entry>
             ... core ...
    <core exit> -> safety -> injection -> scheduling -> compliance -> agent_control
                -> nemo_output_rails -> response_defense -> governance -> END

Any node may short-circuit to END by setting ``terminal`` (policy block,
AI Defense block, NeMo rail, Agent Control deny, clarifying question, generation
error). Adding a guardrail means adding it HERE (and to ``PRE_NODES`` /
``POST_NODES``), never inside a blueprint's core, so both architectures get it
in the same change — tests/test_blueprint_parity.py asserts every compiled
subgraph contains exactly this chain.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List

from langgraph.graph import END, START, StateGraph

from backend.agents.blueprints.base import Blueprint
from backend.agents.nodes.agent_control import agent_control_node, agent_control_prompt_node
from backend.agents.nodes.compliance import compliance_node
from backend.agents.nodes.defense import prompt_defense_node, response_defense_node
from backend.agents.nodes.ehr import ehr_lookup_node
from backend.agents.nodes.governance import governance_node
from backend.agents.nodes.injection import injection_node
from backend.agents.nodes.mcp_thrash import mcp_thrash_join_node, mcp_thrash_launch_node
from backend.agents.nodes.nemo_rails import nemo_input_rails_node, nemo_output_rails_node
from backend.agents.nodes.policy import policy_block_node
from backend.agents.nodes.safety import safety_node
from backend.agents.nodes.scheduling import scheduling_intake_node, scheduling_node
from backend.agents.state import PseudoCoAssistantState

# Screen the PROMPT before any model call. Order matters: the internal policy
# engine is free and deterministic, Cisco AI Defense inspects next, the Agent
# Control prompt-stage controls after it (mirroring its place on output: AI
# Defense keeps the first and last word), NeMo's input rails last.
# scheduling_intake (docs/scheduling.md) runs after the screens: it reads the
# already-vetted message, never calls a model, never terminates.
# ehr_lookup (backend/agents/nodes/ehr.py) runs after the screens too: on a PII/PHI
# exfiltration turn it pulls the synthetic record on file from the mock EHR system
# as a governed tool call, so the synthesizer can ground the PII directive on it.
# mcp_thrash_launch (backend/agents/nodes/mcp_thrash.py) is LAST so it only fires
# on a turn that cleared every prompt screen; it spawns a daemon thread that runs
# the synthetic MCP tool-thrash concurrently with generation and returns at once.
PRE_NODES: List[str] = [
    "policy", "prompt_defense", "agent_control_prompt", "nemo_input_rails", "scheduling_intake",
    "ehr_lookup", "mcp_thrash_launch",
]
# Screen / shape the ANSWER. Cisco AI Defense (response_defense) stays the last
# word on output; governance logs the outcome. scheduling sits before
# compliance so its text is part of the logged response_text and is still
# screened by agent_control / NeMo / AI Defense.
POST_NODES: List[str] = [
    "safety", "injection", "scheduling", "compliance", "agent_control",
    "nemo_output_rails", "response_defense", "mcp_thrash_join", "governance",
]
GUARDRAIL_NODES: List[str] = PRE_NODES + POST_NODES

_NODE_FNS: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    "policy": policy_block_node,
    "prompt_defense": prompt_defense_node,
    "agent_control_prompt": agent_control_prompt_node,
    "nemo_input_rails": nemo_input_rails_node,
    "scheduling_intake": scheduling_intake_node,
    "ehr_lookup": ehr_lookup_node,
    "mcp_thrash_launch": mcp_thrash_launch_node,
    "safety": safety_node,
    "injection": injection_node,
    "scheduling": scheduling_node,
    "compliance": compliance_node,
    "agent_control": agent_control_node,
    "nemo_output_rails": nemo_output_rails_node,
    "response_defense": response_defense_node,
    "mcp_thrash_join": mcp_thrash_join_node,
    "governance": governance_node,
}

# Nodes that may short-circuit (set ``terminal``) and therefore need the
# conditional edge; the rest chain unconditionally.
_MAY_TERMINATE = {"policy", "prompt_defense", "agent_control_prompt", "nemo_input_rails",
                  "agent_control", "nemo_output_rails", "response_defense"}


def _terminal_router(state: Dict[str, Any]) -> str:
    """Conditional-edge function: end the subgraph if a node short-circuited."""
    return "end" if state.get("terminal") else "next"


def _link(g: StateGraph, src: str, dst: str) -> None:
    if src in _MAY_TERMINATE:
        g.add_conditional_edges(src, _terminal_router, {"end": END, "next": dst})
    else:
        g.add_edge(src, dst)


def wire_guardrails(theme_config, blueprint: Blueprint):
    """Build and compile one theme's subgraph: the guardrail chain around the
    blueprint's generation core."""
    g = StateGraph(PseudoCoAssistantState)

    for name in PRE_NODES:
        g.add_node(name, _NODE_FNS[name])
    entry, exit_ = blueprint.build_generation_core(g, theme_config)
    for name in POST_NODES:
        g.add_node(name, _NODE_FNS[name])

    g.add_edge(START, PRE_NODES[0])
    pre_chain = PRE_NODES + [entry]
    for src, dst in zip(pre_chain, pre_chain[1:]):
        _link(g, src, dst)
    # The core's exit may itself short-circuit (generation error, clarifier).
    g.add_conditional_edges(exit_, _terminal_router, {"end": END, "next": POST_NODES[0]})
    for src, dst in zip(POST_NODES, POST_NODES[1:]):
        _link(g, src, dst)
    g.add_edge(POST_NODES[-1], END)

    return g.compile()
