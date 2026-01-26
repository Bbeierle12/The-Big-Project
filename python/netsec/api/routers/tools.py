"""Tools router — list and manage security tools."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from netsec.adapters.base import ToolCategory, ToolStatus

router = APIRouter()


class ToolOut(BaseModel):
    name: str
    display_name: str
    category: str
    description: str
    version: str | None = None
    status: str
    supported_tasks: list[str]


class ToolHealthOut(BaseModel):
    name: str
    status: str


class TaskExecuteRequest(BaseModel):
    task: str
    params: dict = {}


def _get_registry(request: Request):
    """Get adapter registry from app state."""
    registry = getattr(request.app.state, "adapter_registry", None)
    if registry is None:
        raise HTTPException(status_code=503, detail="Adapter registry not initialized")
    return registry


@router.get("/", response_model=list[ToolOut])
async def list_tools(request: Request) -> list[ToolOut]:
    """List all registered security tools."""
    registry = _get_registry(request)
    tools = registry.list_tools()
    return [
        ToolOut(
            name=t.name,
            display_name=t.display_name,
            category=t.category.value,
            description=t.description,
            version=t.version,
            status=t.status.value,
            supported_tasks=t.supported_tasks,
        )
        for t in tools
    ]


@router.get("/health", response_model=list[ToolHealthOut])
async def tools_health(request: Request) -> list[ToolHealthOut]:
    """Health check all tools."""
    registry = _get_registry(request)
    results = await registry.health_check_all()
    return [
        ToolHealthOut(name=name, status=status.value)
        for name, status in results.items()
    ]


@router.get("/{tool_name}", response_model=ToolOut)
async def get_tool(tool_name: str, request: Request) -> ToolOut:
    """Get info about a specific tool."""
    registry = _get_registry(request)
    adapter = registry.get(tool_name)
    if adapter is None:
        raise HTTPException(status_code=404, detail=f"Tool not found: {tool_name}")
    t = adapter.tool_info()
    return ToolOut(
        name=t.name,
        display_name=t.display_name,
        category=t.category.value,
        description=t.description,
        version=t.version,
        status=t.status.value,
        supported_tasks=t.supported_tasks,
    )


@router.get("/{tool_name}/health", response_model=ToolHealthOut)
async def tool_health(tool_name: str, request: Request) -> ToolHealthOut:
    """Health check a specific tool."""
    registry = _get_registry(request)
    adapter = registry.get(tool_name)
    if adapter is None:
        raise HTTPException(status_code=404, detail=f"Tool not found: {tool_name}")
    status = await adapter.health_check()
    return ToolHealthOut(name=tool_name, status=status.value)


@router.post("/{tool_name}/execute")
async def execute_tool(tool_name: str, body: TaskExecuteRequest, request: Request) -> dict:
    """Execute a task on a specific tool."""
    registry = _get_registry(request)
    adapter = registry.get(tool_name)
    if adapter is None:
        raise HTTPException(status_code=404, detail=f"Tool not found: {tool_name}")

    info = adapter.tool_info()
    if info.status != ToolStatus.AVAILABLE:
        raise HTTPException(status_code=503, detail=f"Tool not available: {tool_name}")

    if body.task not in info.supported_tasks and body.task != "custom":
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported task '{body.task}'. Supported: {info.supported_tasks}",
        )

    try:
        result = await adapter.execute(body.task, body.params)
        return {"tool": tool_name, "task": body.task, "result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
