from app.agent import DemoAgent
from app.models import ToolResult, ToolStatus


class RecordingExecutor:
    def __init__(self, result: ToolResult):
        self.result = result
        self.calls = []

    def execute(self, call):
        self.calls.append(call)
        return self.result


def test_agent_uses_injected_executor_not_a_simulated_adapter():
    executor = RecordingExecutor(
        ToolResult(
            status=ToolStatus.SUCCEEDED,
            tool_name="customer.lookup",
            request_id="request-4",
            data={"customer": {"name": "Aurora Labs"}},
        )
    )

    reply = DemoAgent(executor).lookup_customer("demo-user", "Aurora")

    assert reply.message == "Synthetic customer found: Aurora Labs."
    assert executor.calls[0].tool_name == "customer.lookup"


def test_agent_surfaces_denials_without_attempting_an_alternate_path():
    executor = RecordingExecutor(
        ToolResult(
            status=ToolStatus.DENIED,
            tool_name="customer.lookup",
            request_id="request-5",
            reason="denied by policy",
        )
    )

    reply = DemoAgent(executor).lookup_customer("readonly-demo", "Aurora")

    assert reply.message == "I cannot access that customer lookup."
    assert len(executor.calls) == 1
