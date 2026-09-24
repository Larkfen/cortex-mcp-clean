# cortex-mcp

Servidor **MCP (Model Context Protocol)** para **Cortex XDR** de Palo Alto Networks.
Permite que un asistente como **Claude Code** / **Claude Desktop** consulte y opere tu tenant de Cortex en lenguaje natural: casos, incidentes, alertas, endpoints, vulnerabilidades, XQL, threat hunting, IOCs y políticas.

Toda la API REST de Cortex XDR está cubierta a través de la herramienta **`cortex_send_request`** (`path` + `request_data`). El servidor también expone el recurso **`cortex-xdr://reference/rest-api`** con el índice de endpoints oficiales y las reglas de oro de la API.

---

## ⚡ Requisitos previos

- **Python 3.12 o superior** — comprueba con `python --version`.
- **Claude Code** instalado (`claude --version`).
- **Git**.
- Una **API Key de Cortex XDR** (más abajo se explica cómo obtenerla).

## 1. Clona el repositorio

```bash
git clone https://github.com/Larkfen/cortex-mcp-clean.git
cd cortex-mcp-clean
```

---

## 🤖 2. Instalación automática con Claude Code (recomendado)

La forma más simple: **deja que Claude lo instale y configure por ti mientras miras.**
Abre **Claude Code dentro de la carpeta del repo** y pégale este prompt — Claude te irá pidiendo lo que necesite (credenciales, etc.):

```text
Quiero que instales y configures este MCP de Cortex XDR (estás en la raíz del repo) para usarlo desde Claude Code. Haz esto paso a paso:

1. Verifica que tengo Python 3.12+ (python --version). Si no, avísame.
2. Crea un entorno virtual .venv en esta carpeta e instala las dependencias con "pip install ." (o "poetry install" si detectas Poetry). Detecta si estoy en Windows o Linux/macOS y usa los comandos correctos.
3. Pídeme estos tres datos de mi tenant de Cortex XDR (no los inventes):
   - URL base del tenant, formato https://api-<tenant>.xdr.<region>.paloaltonetworks.com
   - API Key ID (el número de la key)
   - API Key (el secreto)
   Recomiéndame usar una key "Advanced" por seguridad; asume Advanced salvo que te diga explícitamente que es Standard.
4. Registra el servidor MCP llamado "cortex-xdr" con `claude mcp add`, donde:
   - command = el python del .venv que creaste
   - args = <ruta-al-repo>/src/main.py
   - cwd = la raíz del repo
   - env = CORTEX_MCP_PAPI_URL, CORTEX_MCP_PAPI_AUTH_ID, CORTEX_MCP_PAPI_AUTH_HEADER, CORTEX_MCP_AUTH_TYPE=advanced y MCP_TRANSPORT=stdio.
   - Si te confirmo que mi key es Standard, usa CORTEX_MCP_AUTH_TYPE=standard.
5. Verifica con /mcp que "cortex-xdr" quede como connected y lístame las tools disponibles.

Reglas: nunca muestres ni subas mi API Key en texto plano fuera de la configuración local del MCP. Si algo falla, muéstrame el error exacto y cómo corregirlo.
```

Eso es todo: Claude crea el entorno, te pide las credenciales, registra el MCP y verifica que quede conectado.
👉 ¿Aún no tienes la API Key de Cortex? Míralo en el [Paso 2 de la instalación manual](#paso-2--obtener-las-credenciales-de-la-api-de-cortex-xdr).
Si prefieres hacerlo tú a mano, sigue la sección de abajo.

---

## 🔧 Instalación manual (paso a paso)

Si prefieres control total, o quieres entender qué hace el prompt, estos son los mismos pasos a mano.
El MCP corre como un proceso local de Python (transport `stdio`); **no necesitas Docker**.

### Paso 1 — Crear el entorno virtual e instalar dependencias

Un *entorno virtual* (`.venv`) es una carpeta aislada con su propio Python y sus librerías, para que las dependencias de este MCP no choquen con el resto de tu sistema. Se crea una sola vez.

**Windows (PowerShell):**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install .
```

**Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install .
```

> Alternativa con Poetry (si lo usas): `poetry install` en vez de `pip install .`.

Al terminar, la ruta del intérprete de Python del entorno será:
- Windows: `<ruta-al-repo>\.venv\Scripts\python.exe`
- Linux/macOS: `<ruta-al-repo>/.venv/bin/python`

Guarda esa ruta; la usarás en el Paso 3.

### Paso 2 — Obtener las credenciales de la API de Cortex XDR

En la consola de **Cortex XDR**:

1. Ve al menú de configuración: **Settings (⚙️) → Configurations → Integrations → API Keys**.
2. Haz clic en **+ New Key**.
3. Elige el tipo de key:
   - **Advanced** ✅ **(recomendado, por seguridad)** — cada petición se firma con un *nonce* + *timestamp* y un hash SHA-256, de modo que la API Key **nunca viaja en texto plano** y se protege contra ataques de *replay*.
   - **Standard** — envía la key directamente en el header. Úsala solo si no puedes usar Advanced.
4. Asigna un **Role** con los permisos que necesites y guarda.
5. Cortex te mostrará **la API Key (secreto)** — cópiala ahora, **solo se muestra una vez**.
6. En la tabla de API Keys, anota el **ID** de la key (un número, p. ej. `1`, `6`, …).

También necesitas la **URL base (FQDN) de tu tenant**. La encuentras en el botón **"Copy examples"** al crear la key, o en la misma página de API Keys. Tiene esta forma:

```
https://api-<tu-tenant>.xdr.<region>.paloaltonetworks.com
```
(el prefijo `api-` es obligatorio; `<region>` suele ser `us`, `eu`, etc.)

En resumen, del Paso 2 sacas **estos datos**:

| Dato | Variable | Ejemplo |
|------|----------|---------|
| URL base del tenant | `CORTEX_MCP_PAPI_URL` | `https://api-<tu-tenant>.xdr.us.paloaltonetworks.com` |
| ID de la API Key | `CORTEX_MCP_PAPI_AUTH_ID` | `1` |
| API Key (secreto) | `CORTEX_MCP_PAPI_AUTH_HEADER` | `xxxxxxxx…` |
| Tipo de key | `CORTEX_MCP_AUTH_TYPE` | `advanced` (recomendado) |

> **Recomendación de seguridad:** usa siempre una key **Advanced** y configura `CORTEX_MCP_AUTH_TYPE=advanced`. Solo si usas una key **Standard** cambia este valor a `standard`.

### Paso 3 — Registrar el MCP en Claude Code

Tienes dos formas equivalentes. Usa **una**.

#### Opción A — Comando `claude mcp add` (rápido)

Ejecuta esto **reemplazando** las rutas y credenciales por las tuyas. En Windows usa `\` en las rutas.

```bash
claude mcp add cortex-xdr \
  --env CORTEX_MCP_PAPI_URL=https://api-<tu-tenant>.xdr.us.paloaltonetworks.com \
  --env CORTEX_MCP_PAPI_AUTH_ID=<tu_api_key_id> \
  --env CORTEX_MCP_PAPI_AUTH_HEADER=<tu_api_key> \
  --env CORTEX_MCP_AUTH_TYPE=advanced \
  --env MCP_TRANSPORT=stdio \
  -- <ruta-al-repo>/.venv/bin/python <ruta-al-repo>/src/main.py
```

#### Opción B — Editar el archivo de configuración MCP

Añade este bloque a tu configuración MCP (el `.mcp.json` del proyecto, o la config de usuario de Claude Code):

```json
{
  "mcpServers": {
    "cortex-xdr": {
      "command": "<ruta-al-repo>/.venv/bin/python",
      "args": ["<ruta-al-repo>/src/main.py"],
      "cwd": "<ruta-al-repo>",
      "env": {
        "CORTEX_MCP_PAPI_URL": "https://api-<tu-tenant>.xdr.us.paloaltonetworks.com",
        "CORTEX_MCP_PAPI_AUTH_ID": "<tu_api_key_id>",
        "CORTEX_MCP_PAPI_AUTH_HEADER": "<tu_api_key>",
        "CORTEX_MCP_AUTH_TYPE": "advanced",
        "MCP_TRANSPORT": "stdio"
      }
    }
  }
}
```

> **Windows:** el `command` es `<ruta-al-repo>\.venv\Scripts\python.exe` y las rutas llevan `\\` (doble) o `/`.
> **Importante:** incluye siempre `cwd` apuntando a la raíz del repo, para que se carguen también las *tools custom* (XQL, block list, etc.).

### Paso 4 — Verificar que funciona

1. Abre Claude Code en la carpeta del proyecto y ejecuta el comando `/mcp`.
2. Debe aparecer **`cortex-xdr`** como **connected**.
3. Prueba pidiéndole algo simple, por ejemplo:
   > "Usa la tool de Cortex para traer la información del tenant (get_tenant_info)."
4. Si conecta pero no ves las tools *custom*, revisa que el `cwd` apunte a la raíz del repo (Paso 3).

En los logs del servidor deberías ver algo como `OpenAPI spec loaded with N path(s)`.

---

## 🧠 Skill incluida — investigación + dashboard

El repo trae un **skill de Claude Code** en [`.claude/skills/cortex-xdr-triage/`](.claude/skills/cortex-xdr-triage/SKILL.md) que le enseña a Claude **cómo usar el MCP bien y con pocos tokens**, sin tener que explicárselo cada vez.

Con el skill activo, puedes pedir en lenguaje natural cosas como *"revisa los casos abiertos y dime qué requiere atención"* y Claude:

1. Lista y **prioriza** los incidentes/casos abiertos (por score y severidad).
2. Investiga cada caso prioritario: **usuario**, **equipo/host**, **qué lo gatilló**, **qué ha pasado** (timeline + MITRE ATT&CK) y **cómo mitigarlo** (con las tools reales).
3. Si lo pides, genera un **dashboard SOC oscuro** (Artifact) estilo consola de Palo Alto, usando la plantilla incluida en `assets/`.

> **Guardas de seguridad del skill:** las tools de lectura corren libres; cualquier acción de contención o cambio (aislar, bloquear, cuarentena, cerrar casos) **se confirma contigo antes de ejecutarse**.

### Cómo activar el skill

- **Dentro del repo:** al abrir Claude Code en esta carpeta, el skill se detecta automáticamente (`.claude/skills/`).
- **Para usarlo en cualquier proyecto:** copia la carpeta a tu config de usuario:

```bash
# Linux/macOS
cp -r .claude/skills/cortex-xdr-triage ~/.claude/skills/
```
```powershell
# Windows
Copy-Item -Recurse .claude\skills\cortex-xdr-triage "$env:USERPROFILE\.claude\skills\"
```

> **Instalación automática vs Skill:** la instalación automática (el prompt de arriba) sirve para **dejar el MCP funcionando**; el **skill** es para **usarlo** (investigar y generar dashboards). Son complementarios.

## 🧰 Tools que expone este MCP

El servidor une automáticamente las especificaciones OpenAPI de:

- **builtin_components/** — herramientas base: `get_issues`, `get_cases`, `get_assets`, `get_filtered_endpoints`, `get_vulnerabilities`, `get_tenant_info`, etc.
- **custom_components/** — herramientas añadidas en este repo: `block_list_add_files`, `xql_run_query`, `xql_get_results`, `get_policy_list`, además de casos/incidentes/alertas, endpoint actions, threat hunting, IOCs, wildfire y políticas.
- **remote_components/** — componentes descargados con el comando de actualización del CLI (opcional).

Para que se vean las tools *custom*, el servidor debe arrancarse **desde el directorio del proyecto** (por eso el `cwd` en la config).

---

## 🩺 Solución de problemas

| Síntoma | Causa probable | Solución |
|--------|----------------|----------|
| `cortex-xdr` no aparece en `/mcp` | Ruta de `command`/`args` incorrecta | Verifica que apunten al `python` del `.venv` y a `src/main.py` (rutas absolutas). |
| Conecta pero solo se ven tools builtin | Falta `cwd` | Añade `cwd` con la raíz del repo (Paso 3). |
| Error 401 / 403 en las llamadas | Credenciales o tipo de key mal | Revisa `CORTEX_MCP_PAPI_AUTH_ID` y `..._AUTH_HEADER`, y que `CORTEX_MCP_AUTH_TYPE` coincida con el tipo real de tu key (`advanced` o `standard`). |
| Error de conexión / DNS | URL base mal formada | Debe empezar con `https://api-` y terminar en `.paloaltonetworks.com`. |
| `No OpenAPI spec or paths loaded` en logs | No arrancó desde el repo | Revisa `cwd`. |

---

## 🛠️ Desarrollo

### Estructura del proyecto
```
src/
├── cli.py                  # Interfaz de línea de comandos
├── main.py                 # Punto de entrada del servidor MCP
├── config/                 # Configuración
├── entities/               # Modelos de datos y recursos
├── pkg/                    # Utilidades internas y cliente PAPI
├── service/                # Capa de servicio (servidor MCP)
└── usecase/                # Lógica de negocio (tools)
    ├── builtin_components/ # Tools base (con OpenAPI)
    ├── custom_components/  # Tools añadidas en este repo
    └── remote_components/  # Tools distribuidas/actualizadas por Cortex
```

### Comandos
```bash
poetry run pytest          # tests
poetry run black .         # formato
poetry run isort .         # orden de imports
```

Para depurar un MCP, lo mejor es el [MCP inspector](https://github.com/modelcontextprotocol/inspector).

---

## 🐳 Docker (opcional)

Solo si prefieres contenedor en vez del método local. Crea un `.env` (copia `.env.example`) y:

```bash
docker build -t cortex-mcp .
```

Registro en el cliente MCP:
```json
{
  "mcpServers": {
    "cortex-xdr": {
      "command": "docker",
      "args": ["run", "--env-file", "/ruta/a/.env", "-i", "--rm", "cortex-mcp"]
    }
  }
}
```

---

## 📄 Licencia

Ver [LICENSE](LICENSE). Este proyecto se basa en la implementación oficial de **Palo Alto Networks**; revisa los términos antes de redistribuir.
