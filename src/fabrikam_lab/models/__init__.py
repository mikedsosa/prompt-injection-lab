"""Pluggable model clients. Every client implements ``ModelClient.chat``."""

from fabrikam_lab.models.base import ChatResponse, ModelClient, ModelError, ToolCall
from fabrikam_lab.models.openai_compat import OpenAICompatClient
from fabrikam_lab.models.stub import ScriptedModel

__all__ = ["ChatResponse", "ModelClient", "ModelError", "OpenAICompatClient", "ScriptedModel", "ToolCall"]
