"""PatchBot: the agentic patch workspace (docs/patchbot.md).

A synthetic server estate per attendee, a scanner that reports over MCP, a
Change Board, synthetic patches, and an agent that works the findings on the
box's own model. Every tool call the agent makes is judged before it runs by
Splunk Agent Observability Controls (``controls.py``), traced in its own Agent
stream, and sent to Splunk under the ``pseudoco:patchbot:*`` sourcetypes
(TA-patchbot). Nothing here touches the chat pipeline or the governance log.
"""
