from __future__ import annotations

from .types import Action


class ToolEnvironment:
    def __init__(self, available_tools: set[str] | None = None) -> None:
        self.available_tools = available_tools or {"read_email", "send_email", "delete_email"}
        self.effects: list[Action] = []

    def execute(self, action: Action) -> bool:
        if action.tool not in self.available_tools:
            return False
        self.effects.append(action)
        return True
