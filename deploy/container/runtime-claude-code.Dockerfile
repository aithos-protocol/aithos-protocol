# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mathieu Colla
#
# aithos/runtime-claude-code — the cage (SPEC-container-runtime §13.4).
# Executes the agent (Claude Code, headless). Holds NO authority and, by
# default, no secret. Attached ONLY to the internal cage network: its sole
# reachable host is the gateway. The mandate is a physical boundary here, not a
# convention — this image cannot open a socket to anything but the gateway.
#
# Bring-your-own-agent: swap this image for any agent that can point its model
# base-URL at $AITHOS_GATEWAY_URL/llm and speak MCP to $AITHOS_GATEWAY_URL/mcp.

FROM node:20-bookworm-slim

# Claude Code, the first reference agent. Pinned major; the cage makes
# --dangerously-skip-permissions safe (there is nothing unsafe to reach).
RUN npm install -g @anthropic-ai/claude-code@^1 \
 && npm cache clean --force

# Non-root agent user; the entrypoint writes only to tmpfs mounts.
RUN useradd --create-home --uid 10001 agent
USER agent
WORKDIR /home/agent

COPY --chown=agent:agent entrypoint-runtime.sh /usr/local/bin/entrypoint-runtime.sh

# The cage exposes NO port (N2): work is pulled, never pushed in.
# Contract for any agent placed here:
#   AITHOS_GATEWAY_URL   base URL of the gateway (MCP at /mcp, LLM at /llm)
#   AITHOS_MCP_TOKEN     short-lived session bearer minted at boot
#   AITHOS_MISSION       (job mode) the single mission to run, then exit
ENTRYPOINT ["/usr/local/bin/entrypoint-runtime.sh"]
