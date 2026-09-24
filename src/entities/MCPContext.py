from dataclasses import dataclass
from typing import Any

@dataclass
class MCPContext:
    auth_headers: dict[str, str]
    papi_client: Any = None  # PAPIClient compartido (misma instancia que OpenAPI)
