import io
import logging
import os
from typing import Optional

from fastmcp import Context

from config.config import get_config
from entities.MCPContext import MCPContext
from pkg.client import AdvancedPAPIClient, PAPIClient
from pkg.cortex_api import build_cortex_payload, normalize_cortex_path
from pkg.util import get_papi_auth_headers, get_papi_auth_headers_advanced, get_papi_url

logger = logging.getLogger(__name__)

# Credenciales con las que se creó el PAPIClient en main; se fijan en initialize_mcp_server
_startup_api_key: str = ""
_startup_api_key_id: str = ""


def set_startup_credentials(api_key: str, api_key_id: str) -> None:
    """Fijar credenciales de arranque para que get_fetcher use las mismas que el PAPIClient."""
    global _startup_api_key, _startup_api_key_id
    _startup_api_key = api_key or ""
    _startup_api_key_id = api_key_id or ""


class Fetcher:
    """
    Fetcher class for interacting with public API endpoints.
    Si se pasa shared_client (mismo PAPIClient/AdvancedPAPIClient que OpenAPI), se usa ese y no se crea otro.
    """

    def __init__(self, url: str, api_key: str, api_key_id: str, shared_client: Optional[PAPIClient | AdvancedPAPIClient] = None, auth_type: str = "standard") -> None:
        self.url = url
        self.api_key = api_key
        self.api_key_id = api_key_id
        self.shared_client = shared_client
        self.auth_type = auth_type

    def _build_path(
        self,
        path: str,
        omit_papi_prefix: bool,
        api_version: str = "v1",
        trailing_slash: Optional[bool] = None,
    ) -> str:
        if omit_papi_prefix:
            built = path
        else:
            # Regla de oro Cortex: URL DEBE terminar en /
            if "/public_api/" not in path:
                built = normalize_cortex_path(path, api_version)
            else:
                built = path.rstrip("/") + "/" if path else path
            if trailing_slash is False:
                built = built.rstrip("/")
        if trailing_slash is True and not built.endswith("/"):
            built = built + "/"
        return built

    async def send_request(
        self,
        path: str,
        method: str = "POST",
        data: Optional[dict | str] = None,
        headers: Optional[dict] = None,
        omit_papi_prefix: bool = False,
        stream: bool = False,
        api_version: str = "v1",
        trailing_slash: Optional[bool] = None,
    ) -> dict | io.BytesIO:
        path = self._build_path(path, omit_papi_prefix, api_version=api_version, trailing_slash=trailing_slash)
        if self.shared_client is not None:
            if stream:
                return await self.shared_client.stream(method, path, data=data, headers=headers)
            return await self.shared_client.request(method, path, json=data if isinstance(data, dict) else None, headers=headers)

        if self.auth_type == "advanced":
            async with AdvancedPAPIClient(self.url, self.api_key, self.api_key_id) as client:
                if stream:
                    result = await client.stream(method, path, data=data, headers=headers)
                else:
                    result = await client.request(method, path, json=data, headers=headers)
        else:
            auth_headers = get_papi_auth_headers(self.api_key, self.api_key_id)
            req_headers = {**auth_headers, "Content-Type": "application/json"}
            if headers:
                req_headers.update(headers)
            async with PAPIClient(self.url, auth_headers) as client:
                if stream:
                    result = await client.stream(method, path, data=data, headers=req_headers)
                else:
                    result = await client.request(method, path, json=data, headers=req_headers)
        return result


async def get_fetcher(ctx: Context) -> Fetcher:
    """
    Devuelve un Fetcher que usa el PAPIClient compartido (misma instancia que OpenAPI) si está en el lifespan.
    Así issue/search y case/search usan exactamente el mismo cliente que get_tenant_info, get_assets, etc.
    """
    config = get_config()
    url = get_papi_url(config.papi_url_env_key)
    api_key = _startup_api_key or config.papi_auth_header_key
    xdr_id = _startup_api_key_id or config.papi_auth_id_key
    shared_client = None
    try:
        lifespan: MCPContext = ctx.request_context.lifespan_context
        if lifespan and getattr(lifespan, "papi_client", None) is not None:
            shared_client = lifespan.papi_client
        if (not api_key or not xdr_id) and lifespan and lifespan.auth_headers:
            a = lifespan.auth_headers.get("Authorization")
            b = lifespan.auth_headers.get("x-xdr-auth-id") or lifespan.auth_headers.get("X-XDR-AUTH-ID")
            if a and b:
                api_key, xdr_id = a, b
    except (AttributeError, TypeError):
        pass

    auth_type = getattr(config, "papi_auth_type", "standard") or "standard"
    logger.info(f"Creating new fetcher for auth ID {xdr_id}, shared_client={shared_client is not None}, auth_type={auth_type}")
    fetcher = Fetcher(url, api_key, xdr_id, shared_client=shared_client, auth_type=auth_type)
    ctx.set_state("fetcher", fetcher)
    return fetcher
