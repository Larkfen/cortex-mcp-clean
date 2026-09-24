import io
import json as _json_mod
import logging
import math
import re

import httpx
from httpx import ConnectError, RequestError, TimeoutException

from config.config import get_config
from entities.exceptions import (
    PAPIAuthenticationError,
    PAPIClientError,
    PAPIClientRequestError,
    PAPIConnectionError,
    PAPIResponseError,
    PAPIServerError,
)

logger = logging.getLogger(__name__)


class PAPIClient(httpx.AsyncClient):
    def __init__(self, base_url: str, headers: dict[str, str], timeout: int = 30, **kwargs):
        """
        Initialize PAPIClient as an AsyncClient.

        Args:
            base_url (str): Base URL for the PAPI server
            headers (dict): default headers for PAPI
            timeout (int): Request timeout in seconds
            **kwargs: Additional arguments passed to httpx.AsyncClient
        """
        if "timeout" not in kwargs:
            kwargs["timeout"] = timeout
        super().__init__(base_url=base_url, headers=headers, **kwargs)

    def _get_default_headers(self) -> dict:
        """Get default headers with authentication."""
        headers = dict(self.headers)
        headers.update({
            "Content-Type": "application/json",
            "X-IS-MCP": "true",
        })
        return headers

    def _get_download_default_headers(self) -> dict:
        """Get default headers for download/stream."""
        headers = dict(self.headers)
        headers.update({"Content-Type": "application/zip"})
        return headers

    @staticmethod
    def _normalize_cortex_body(body: dict | None, url_str: str = "") -> dict:
        """Asegura request_data como dict para Cortex PAPI. Usado en request() y send()."""
        if body is None:
            out = {"request_data": {}}
        elif "request_data" not in body:
            out = {**body, "request_data": {}}
        else:
            rd = body["request_data"]
            if rd is None:
                out = {**body, "request_data": {}}
            elif isinstance(rd, str):
                try:
                    out = {**body, "request_data": _json_mod.loads(rd) if rd.strip() else {}}
                except (ValueError, TypeError):
                    out = {**body, "request_data": {}}
            else:
                out = body
        # API de vulnerabilidades exige use_page_token
        if url_str and "get_vulnerabilities" in url_str:
            out["request_data"].setdefault("use_page_token", True)
        return out

    async def send(self, request: httpx.Request, **kwargs) -> httpx.Response:
        """Intercepta send() (parser experimental OpenAPI) para normalizar body Cortex."""
        url_str = str(request.url)
        # Quitar Content-Length al reenviar para que httpx lo recalcule con el body nuevo
        def headers_sin_content_length(h):
            return {k: v for k, v in h.items() if k.lower() != "content-length"}
        if "public_api" in url_str and request.content:
            try:
                raw = request.content.decode("utf-8")
                body = None
                try:
                    body = _json_mod.loads(raw)
                except _json_mod.JSONDecodeError:
                    # Reintentar tras normalizar literales Python (True/False/None)
                    raw2 = re.sub(r":\s*True\b", ": true", raw)
                    raw2 = re.sub(r":\s*False\b", ": false", raw2)
                    raw2 = re.sub(r":\s*None\b", ": null", raw2)
                    raw2 = re.sub(r",\s*True\b", ", true", raw2)
                    raw2 = re.sub(r",\s*False\b", ", false", raw2)
                    raw2 = re.sub(r",\s*None\b", ", null", raw2)
                    body = _json_mod.loads(raw2)
                if isinstance(body, dict):
                    body = self._normalize_cortex_body(body, url_str)
                    new_content = _json_mod.dumps(body).encode()
                    request = httpx.Request(
                        request.method,
                        request.url,
                        content=new_content,
                        headers=headers_sin_content_length(dict(request.headers)),
                    )
            except (ValueError, TypeError, _json_mod.JSONDecodeError):
                pass
        elif "public_api" in url_str and request.method in ("POST", "PUT", "PATCH") and not request.content:
            body = self._normalize_cortex_body(None, url_str)
            new_content = _json_mod.dumps(body).encode()
            request = httpx.Request(
                request.method,
                request.url,
                content=new_content,
                headers=headers_sin_content_length(dict(request.headers)),
            )
        return await super().send(request, **kwargs)

    async def request(self, method: str, url: str,
                      *,
        content = None,
        data = None,
        files = None,
        json = None,
        params = None,
        headers = None,
        cookies = None,
        timeout = None) -> dict:
        """
        Send an HTTP request to the PAPI server asynchronously.

        Args:
            method (str): HTTP method (GET, POST, PUT, DELETE, etc.)
            url (str): API endpoint path to append to the base URL
            data (dict, optional): Request payload data. Will be JSON serialized.
            headers (dict, optional): Custom HTTP headers. If not provided, default
                                    headers with authentication will be used.

        Returns:
            dict: Parsed JSON response from the server

        Raises:
            PAPIConnectionError: Raised when there are network connectivity issues:
                - Connection cannot be established to the server
                - Request timeout occurs
                - General network/transport errors
                - DNS resolution failures

            PAPIAuthenticationError: Raised for authentication/authorization failures:
                - 401 Unauthorized: Invalid API key or credentials
                - 403 Forbidden: Valid credentials but insufficient permissions

            PAPIClientRequestError: Raised for client-side request errors (4xx):
                - 400 Bad Request: Invalid request format or parameters
                - 404 Not Found: Requested resource doesn't exist
                - 405 Method Not Allowed: HTTP method not supported for endpoint
                - 409 Conflict: Request conflicts with current server state
                - 422 Unprocessable Entity: Request validation failed
                - Other 4xx status codes

            PAPIServerError: Raised for server-side errors (5xx):
                - 500 Internal Server Error: Unexpected server error
                - 502 Bad Gateway: Invalid response from upstream server
                - 503 Service Unavailable: Server temporarily unavailable
                - 504 Gateway Timeout: Upstream server timeout
                - Other 5xx status codes

            PAPIResponseError: Raised for invalid or malformed responses:
                - Server returns None response
                - Invalid JSON in response body
                - Unexpected HTTP status codes outside standard ranges

            PAPIClientError: Raised for unexpected errors that don't fit other categories:
                - Unexpected exceptions during request processing
                - Programming errors or edge cases

        Example:
            >>> async with PAPIClient("https://api.example.com", {"Authorization": "XXX"}) as client:
            ...     try:
            ...         result = await client.request("GET", "/endpoints")
            ...     except PAPIAuthenticationError:
            ...         print("Check your API credentials")
            ...     except PAPIConnectionError:
            ...         print("Network connection issue")
            ...     except PAPIServerError:
            ...         print("Server is experiencing issues")
        """
        if headers is None:
            headers = self._get_default_headers()
        else:
            # Merge with default headers, allowing custom headers to override
            default_headers = self._get_default_headers()
            default_headers.update(headers)
            headers = default_headers

        # Platform API "Create Public Policy" (path policy) espera body en raíz, sin request_data
        skip_wrapper = (headers.pop("X-Cortex-Raw-Body", None) or headers.pop("x-cortex-raw-body", None)) == "true"

        full_url = f'{self.base_url}{url}'
        logger.info(f'Sending async request to {full_url}')

        # Cortex PAPI exige body con request_data (objeto). Normalizar body (json, data o vacío).
        body = json if json is not None else data
        if "public_api" in url and (body is None or isinstance(body, dict)) and not skip_wrapper:
            body = self._normalize_cortex_body(body, url)
            json = body
            data = None

        try:
            response = await super().request(
                method=method,
                url=url,
                data=data,
                params=params,
                headers=headers,
                cookies=cookies,
                timeout=timeout if timeout else self.timeout,
                json=json,
                content=content,
            )
        except ConnectError as e:
            logger.exception(f'Connection failed for request to {url}: {e}')
            raise PAPIConnectionError(f'Failed to connect to PAPI server at {url}: {e}') from e
        except TimeoutException as e:
            logger.exception(f'Request timeout for request to {url}: {e}')
            raise PAPIConnectionError(f'Request timeout for {url}: {e}') from e
        except RequestError as e:
            logger.exception(f'Request failed for request to {url}: {e}')
            raise PAPIConnectionError(f'Request failed for {url}: {e}') from e
        except Exception as e:
            logger.exception(f'Unexpected error sending request to {url}: {e}')
            raise PAPIClientError(f'Unexpected error for request to {url}: {e}') from e

        if response is None:
            err_msg = f'Received None response from server for request to {url}'
            logger.error(err_msg)
            raise PAPIResponseError(err_msg)

        # Handle different HTTP status codes more specifically
        if response.status_code == 401:
            err_msg = f'Authentication failed for request to {url}: {response.text}'
            logger.error(err_msg)
            raise PAPIAuthenticationError(err_msg)
        elif response.status_code == 403:
            err_msg = f'Authorization failed for request to {url}: {response.text}'
            logger.error(err_msg)
            raise PAPIAuthenticationError(err_msg)
        elif 400 <= response.status_code < 500:
            err_msg = f'Client error for request to {url}: {response.text} [{response.status_code}]'
            logger.error(err_msg)
            raise PAPIClientRequestError(err_msg)
        elif 500 <= response.status_code < 600:
            err_msg = f'Server error for request to {url}: {response.text} [{response.status_code}]'
            logger.error(err_msg)
            raise PAPIServerError(err_msg)
        elif response.status_code < 200 or response.status_code >= 300:
            err_msg = f'Unexpected response code for request to {url}: {response.text} [{response.status_code}]'
            logger.error(err_msg)
            raise PAPIResponseError(err_msg)

        try:
            raw_text = response.text
            # Algunos endpoints Cortex devuelven NaN/Infinity (no válidos en JSON estándar); sanitizar antes de parsear.
            sanitized = re.sub(r":\s*(-?)Infinity\b", r": null", raw_text)
            sanitized = re.sub(r",\s*(-?)Infinity\b", r", null", sanitized)
            sanitized = re.sub(r"\[\s*(-?)Infinity\b", r"[ null", sanitized)
            sanitized = re.sub(r":\s*NaN\b", ": null", sanitized, flags=re.IGNORECASE)
            sanitized = re.sub(r",\s*NaN\b", ", null", sanitized, flags=re.IGNORECASE)
            sanitized = re.sub(r"\[\s*NaN\b", "[ null", sanitized, flags=re.IGNORECASE)
            data = _json_mod.loads(sanitized)
            # Garantizar serialización segura para MCP: nan/inf -> null, demás no serializables -> str
            def _json_default(obj):
                if isinstance(obj, float) and (math.isnan(obj) or math.isinf(obj)):
                    return None
                raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")
            return _json_mod.loads(_json_mod.dumps(data, default=_json_default))
        except _json_mod.JSONDecodeError as e:
            err_msg = f'Invalid JSON response from server for request to {url}: {e}'
            logger.error(err_msg)
            raise PAPIResponseError(err_msg) from e

    async def stream(self, method: str, url: str,
            *,
            content=None,
            data=None,
            files=None,
            json=None,
            params=None,
            headers=None,
            cookies=None,
            timeout=None
    ) -> io.BytesIO | None:
        """
            Asynchronously downloads a file from a URL using httpx streaming
            and returns it as an in-memory bytes buffer.

            This method is memory-efficient as it doesn't load the entire file
            into memory at once.

            Args:
                url: The URL of the zip file to download.
                data (dict, optional): Request payload data. Will be JSON serialized.
                headers (dict, optional): Custom HTTP headers. If not provided, default
                                        headers with authentication will be used.

            Returns:
                An io.BytesIO object containing the downloaded zip file data,
                or None if the download failed.

            Raises:
                Same exceptions as request() method for consistency.
            """
        logger.info(f"Attempting to download MCP server content from: {url}")

        if headers is None:
            headers = self._get_download_default_headers()
        else:
            # Merge with default headers, allowing custom headers to override
            default_headers = self._get_download_default_headers()
            default_headers.update(headers)
            headers = default_headers

        try:
            # Use io.BytesIO to create an in-memory binary buffer.
            zip_buffer = io.BytesIO()

            async with super().stream(
                    method=method,
                    url=url,
                    data=data,
                    params=params,
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout if timeout else self.timeout,
                    json=json,
                    content=content,
                    follow_redirects=True) as response:

                # Helper function to safely get response content for error messages
                async def get_response_content() -> str:
                    try:
                        # For streaming responses, we need to read the content
                        content_bytes = b""
                        async for res_chunk in response.aiter_bytes():
                            content_bytes += res_chunk
                            # Limit content size for error messages (first 1000 chars)
                            if len(content_bytes) > get_config().http_response_error_message_max_size:
                                break
                        return content_bytes.decode('utf-8', errors='ignore')
                    except Exception:
                        return f"Unable to read response content (status: {response.status_code})"

                # Handle different HTTP status codes using the same pattern as request()
                if response.status_code == 401:
                    response_text = await get_response_content()
                    err_msg = f'Authentication failed for request to {url}: {response_text}'
                    logger.error(err_msg)
                    raise PAPIAuthenticationError(err_msg)
                elif response.status_code == 403:
                    response_text = await get_response_content()
                    err_msg = f'Authorization failed for request to {url}: {response_text}'
                    logger.error(err_msg)
                    raise PAPIAuthenticationError(err_msg)
                elif 400 <= response.status_code < 500:
                    response_text = await get_response_content()
                    err_msg = f'Client error for request to {url}: {response_text} [{response.status_code}]'
                    logger.error(err_msg)
                    raise PAPIClientRequestError(err_msg)
                elif 500 <= response.status_code < 600:
                    response_text = await get_response_content()
                    err_msg = f'Server error for request to {url}: {response_text} [{response.status_code}]'
                    logger.error(err_msg)
                    raise PAPIServerError(err_msg)
                elif response.status_code < 200 or response.status_code >= 300:
                    response_text = await get_response_content()
                    err_msg = f'Unexpected response code for request to {url}: {response_text} [{response.status_code}]'
                    logger.error(err_msg)
                    raise PAPIResponseError(err_msg)

                # If we get here, the response was successful (2xx)
                # Get the total file size from headers if available.
                total_size = int(response.headers.get("Content-Length", 0))
                downloaded_size = 0

                # Iterate over the response content in chunks asynchronously.
                async for chunk in response.aiter_bytes():
                    zip_buffer.write(chunk)
                    downloaded_size += len(chunk)
                    if total_size > 0:
                        # Display download progress.
                        progress = (downloaded_size / total_size) * 100
                        logger.info(f"\rDownloading... {progress:.2f}% complete")

                logger.info("\nDownload finished successfully.")

        except ConnectError as e:
            logger.exception(f'Connection failed for request to {url}: {e}')
            raise PAPIConnectionError(f'Failed to connect to PAPI server at {url}: {e}') from e
        except TimeoutException as e:
            logger.exception(f'Request timeout for request to {url}: {e}')
            raise PAPIConnectionError(f'Request timeout for {url}: {e}') from e
        except RequestError as e:
            logger.exception(f'Request failed for request to {url}: {e}')
            raise PAPIConnectionError(f'Request failed for {url}: {e}') from e
        except (PAPIAuthenticationError, PAPIClientRequestError, PAPIServerError, PAPIResponseError):
            # Re-raise our custom exceptions without wrapping
            raise
        except Exception as e:
            logger.exception(f'Unexpected error sending request to {url}: {e}')
            raise PAPIClientError(f'Unexpected error for request to {url}: {e}') from e

        # Reset the buffer's position to the beginning (0).
        # This is crucial so that other libraries (like zipfile) can read it from the start.
        zip_buffer.seek(0)
        return zip_buffer


class AdvancedPAPIClient(PAPIClient):
    """
    PAPIClient that regenerates Advanced HMAC auth headers on every request.
    Extends PAPIClient so it inherits JSON parsing, status code handling,
    body normalization (request_data), and NaN/Infinity sanitization.
    """

    def __init__(self, base_url: str, api_key: str, api_key_id: str, timeout: int = 30, **kwargs):
        from pkg.util import get_papi_auth_headers_advanced
        initial_headers = get_papi_auth_headers_advanced(api_key, api_key_id)
        super().__init__(base_url=base_url, headers=initial_headers, timeout=timeout, **kwargs)
        self._adv_api_key = api_key
        self._adv_api_key_id = api_key_id

    def _get_default_headers(self) -> dict:
        from pkg.util import get_papi_auth_headers_advanced
        headers = get_papi_auth_headers_advanced(self._adv_api_key, self._adv_api_key_id)
        headers["Content-Type"] = "application/json"
        headers["X-IS-MCP"] = "true"
        return headers

    async def send(self, request: httpx.Request, **kwargs) -> httpx.Response:
        from pkg.util import get_papi_auth_headers_advanced
        fresh = get_papi_auth_headers_advanced(self._adv_api_key, self._adv_api_key_id)
        fresh["Content-Type"] = "application/json"
        fresh["X-IS-MCP"] = "true"
        old_headers = dict(request.headers)
        for ok in list(old_headers):
            if ok.lower() in ("authorization", "x-xdr-auth-id", "x-xdr-nonce", "x-xdr-timestamp"):
                del old_headers[ok]
        merged = {**old_headers, **fresh}
        if "content-length" in {k.lower() for k in merged}:
            merged = {k: v for k, v in merged.items() if k.lower() != "content-length"}
        request = httpx.Request(
            request.method, request.url, content=request.content, headers=merged,
        )
        return await super().send(request, **kwargs)
