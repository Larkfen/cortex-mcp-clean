# cortex-mcp

A Python based integration for Cortex MCP (Model Context Protocol).

## Cortex XDR REST API (cobertura completa vía `cortex_send_request`)

Los endpoints documentados en [Cortex XDR REST API](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Cortex-XDR-REST-API) se invocan con la herramienta **`cortex_send_request`** (`path` + `request_data`), salvo los que requieran `cortex_universal_api` (`use_raw_body`).

El servidor expone el recurso MCP **`cortex-xdr://reference/rest-api`** (markdown en `src/entities/resources/cortex_rest_api_reference.md`): índice de enlaces oficiales por módulo (Audit, Auth, Datasets, Endpoints, Incidents, Response, Scripts, Syslog, System, XQL) y reglas de oro.

**`cortex_xql_query`** prueba automáticamente `xql/start_xql_query` y `xql_queries/run` según lo que acepte el tenant.

## Getting Started

### Prerequisites

- Python 3.13 or higher / container environment
- Cortex API credentials (Standard API key and API key ID)

### Installation

#### Option 1: Using Docker

Create a `.env` file with the following environment variables:
```
CORTEX_MCP_PAPI_URL=https://<your-tenant-url>,
CORTEX_MCP_PAPI_AUTH_HEADER=<your_api_key>, 
CORTEX_MCP_PAPI_AUTH_ID=<your_api_key_id>,
(optional - defaults to stdio)MCP_TRANSPORT=stdio/streamable-http
(optional, for streamable-http)MCP_HOST=0.0.0.0
(optional, for streamable-http)MCP_PORT=8080
(optional, for streamable-http)MCP_PATH=/api/v1/stream/mcp
```

Build the Docker container:

```bash
docker build -t cortex-mcp .
```

#### Option 2: Locally Using Poetry (Virtual Environment)

1. Install Poetry if you haven't already:
```bash
curl -sSL https://install.python-poetry.org | python3 -
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate
```

3. Install project dependencies:
```bash
poetry install
```

### Running The MCP Server

#### CLI
- See the [CLI](src/README.md) readme

#### Claude Desktop

-  Open the Claude configuration file (accessible from the `Developer` pane in Claude Desktop settings) and add the following MCP server configuration:


Docker Container:
```json
{
  "mcpServers": {
    "Cortex MCP Server": {
      "command": "docker",
      "args": [
        "run",
        "--env-file",
        "/path/to/.env",
        "-i",
        "--rm",
        "cortex-mcp"
      ]
    }
  }
}
```


Local (the mcp server would have to be [installed locally beforehand](#option-2-locally-using-poetry-virtual-environment)):
```json
{
  "mcpServers": {
    "Cortex MCP Server": {
      "command": "<path to cortex-mcp virtual environment>/bin/python",
      "args": [
        "<path to cortex-mcp>/src/main.py"
      ],
       "env": {
          "CORTEX_MCP_PAPI_URL": "https://<your-tenant-url>",
          "CORTEX_MCP_PAPI_AUTH_HEADER": "<your_api_key>", 
          "CORTEX_MCP_PAPI_AUTH_ID": "<your_api_key_id>",
          "MCP_TRANSPORT": "<stdio/streamable-http>"
   }
    }
  }
}
```

#### Claude Code

Regístralo con el CLI de Claude Code (ejecuta el comando desde la raíz de este repo):

```bash
claude mcp add cortex-xdr \
  --env CORTEX_MCP_PAPI_URL=https://api-<tu-tenant>.xdr.<region>.paloaltonetworks.com \
  --env CORTEX_MCP_PAPI_AUTH_ID=<tu_api_key_id> \
  --env CORTEX_MCP_PAPI_AUTH_HEADER=<tu_api_key> \
  --env MCP_TRANSPORT=stdio \
  -- <ruta-al-venv>/bin/python <ruta-a-este-repo>/src/main.py
```

O de forma equivalente, añade este bloque a tu configuración de MCP (`.mcp.json` del proyecto, o la config de usuario de Claude Code):

```json
{
  "mcpServers": {
    "cortex-xdr": {
      "command": "<ruta-al-venv>/bin/python",
      "args": ["<ruta-a-este-repo>/src/main.py"],
      "cwd": "<ruta-a-este-repo>",
      "env": {
        "CORTEX_MCP_PAPI_URL": "https://api-<tu-tenant>.xdr.<region>.paloaltonetworks.com",
        "CORTEX_MCP_PAPI_AUTH_ID": "<tu_api_key_id>",
        "CORTEX_MCP_PAPI_AUTH_HEADER": "<tu_api_key>",
        "MCP_TRANSPORT": "stdio"
      }
    }
  }
}
```

> En Windows usa rutas con `\\` o con `/`, y el ejecutable `.../Scripts/python.exe` del venv.

### Tools que expone este MCP

El servidor une las specs OpenAPI de:

- **builtin_components/openapi/** — herramientas que vienen con el paquete (p. ej. get_issues, get_cases, get_assets, get_filtered_endpoints, get_vulnerabilities, etc.).
- **custom_components/openapi/** — herramientas añadidas en este repo: `block_list_add_files`, `xql_run_query`, `xql_get_results`, `get_policy_list`.
- **remote_components/openapi/** — componentes descargados con el comando de actualización del CLI (opcional).

Para que el cliente MCP (Claude Code, Claude Desktop, etc.) vea las tools custom, el servidor debe arrancarse **desde el directorio de este proyecto** (donde existe `src/usecase/custom_components/openapi/`) — por eso el bloque de configuración incluye `cwd`. Si usas la ruta al `main.py` o al venv de este repo, las tools custom se cargan. Si el cliente arranca un paquete instalado globalmente en otro path, puede que solo vea las builtin.

En los logs del servidor deberías ver algo como: `OpenAPI spec loaded with N path(s)`; si N es bajo o ves el warning "No OpenAPI spec or paths loaded", revisa que existan las carpetas anteriores.

## Development

### Project Structure
```
src/
├── cli.py                           # Command line interface
├── main.py                          # Main application entry point
├── config/                          # Configuration modules
├── entities/                        # Data models and entity classes
├── pkg/                             # Internal package utilities and helpers
├── service/                         # Service layer implementations
└── usecase/                         # Business logic and use cases
    ├── builtin_components/          # MCP components that come with the package
    │   ├── openapi/
    │   └── python modules
    ├── custom_components/           # MCP components that are user-defined 
    │   ├── openapi/
    │   └── python modules
    └── remote_components/           # MCP components that are distributed and updated by Cortex** 
        ├── openapi/
        └── python modules

tests/
├── e2e/                             # End-to-end tests
└── individual test files
```
** When the user runs the [CLI](src/README.md) update command, any new or updated components provided by Cortex are automatically downloaded into the remote_components folder.  
During each update, the folder is fully replaced and all existing contents are recreated.

Do not add custom tools to this directory, as it is managed entirely by Cortex and will be overwritten on every update.

### Adding custom MCP components

To add custom MCP components, follow this [guide](src/usecase/README.md).

### Coding

Run tests:
```bash
poetry run pytest
```

Format code:
```bash
poetry run black .
poetry run isort .
```

Debug:
The best way to debug MCP servers is with the [MCP inspector](https://github.com/modelcontextprotocol/inspector).
Aside from that, end-to-end tests can be run and added under `tests/e2e`.

