import asyncio
import logging
from typing import Annotated

from fastmcp import Context, FastMCP
from pydantic import Field

from entities.exceptions import (
    PAPIAuthenticationError, PAPIClientError, PAPIClientRequestError,
    PAPIConnectionError, PAPIResponseError, PAPIServerError,
)
from pkg.util import create_response
from usecase.base_module import BaseModule
from usecase.fetcher import get_fetcher

logger = logging.getLogger(__name__)

_DEFAULT_TIMEFRAME_MINUTES = 1440  # 24h
_POLL_INTERVAL_S = 2
_MAX_POLL_S = 90

_PAPI_ERRORS = (
    PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
    PAPIClientRequestError, PAPIResponseError, PAPIClientError,
)


async def _run_hunt_query(fetcher, query: str, timeframe_minutes: int) -> dict:
    payload = {
        "request_data": {
            "query": query,
            "timeframe": {"relativeTime": timeframe_minutes * 60 * 1000},
        }
    }
    start = await fetcher.send_request("xql/start_xql_query/", data=payload)
    reply = start.get("reply", {})
    execution_id = reply.get("execution_id") if isinstance(reply, dict) else reply

    if not execution_id:
        return {"error": "No execution_id returned", "raw": start}

    poll_payload = {"request_data": {"query_id": execution_id, "expected_result_type": "JSON"}}
    waited = 0
    while waited < _MAX_POLL_S:
        await asyncio.sleep(_POLL_INTERVAL_S)
        waited += _POLL_INTERVAL_S
        poll = await fetcher.send_request("xql/get_query_results/", data=poll_payload)
        r = poll.get("reply", {})
        status = r.get("status")
        if status == "SUCCESS":
            results = r.get("results", {})
            data = results.get("data", []) if isinstance(results, dict) else []
            return {"hit_count": len(data), "results": data, "execution_id": execution_id}
        if status in ("FAILED", "CANCELED"):
            return {"error": f"Query {status}", "execution_id": execution_id}

    return {"error": f"Timeout after {_MAX_POLL_S}s", "execution_id": execution_id}


async def hunt_lateral_movement(
    ctx: Context,
    timeframe_minutes: Annotated[int, Field(description="Lookback in minutes (default 1440 = 24h)", default=_DEFAULT_TIMEFRAME_MINUTES)] = _DEFAULT_TIMEFRAME_MINUTES,
) -> str:
    """
    Hunt for lateral movement indicators: PsExec, WMI remote execution,
    remote service creation, admin share access (C$, ADMIN$, IPC$).
    MITRE: T1021 (Remote Services), T1047 (WMI), T1570 (Lateral Tool Transfer).

    Args:
        ctx: FastMCP context.
        timeframe_minutes: Lookback window.

    Returns:
        JSON with hit count and matching events.
    """
    query = """dataset=xdr_data
| filter (
    actor_process_image_name in ("psexec.exe", "psexec64.exe", "paexec.exe")
    or (event_type = ENUM.NETWORK and action_remote_port in (135, 445))
    or (actor_process_image_name = "wmiprvse.exe" and action_process_image_name != null)
    or (action_network_creation_type = "SMB" and action_remote_path contains "ADMIN$")
    or (action_remote_path contains "C$" and event_type = ENUM.NETWORK)
)
| fields event_timestamp, host_name, actor_process_image_name, action_process_image_name, action_remote_ip, action_remote_port, action_remote_path
| limit 50"""
    try:
        fetcher = await get_fetcher(ctx)
        result = await _run_hunt_query(fetcher, query, timeframe_minutes)
        result["hunt"] = "lateral_movement"
        result["mitre"] = ["T1021", "T1047", "T1570"]
        return create_response(data=result)
    except _PAPI_ERRORS as e:
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"hunt_lateral_movement failed: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def hunt_persistence(
    ctx: Context,
    timeframe_minutes: Annotated[int, Field(description="Lookback in minutes (default 1440 = 24h)", default=_DEFAULT_TIMEFRAME_MINUTES)] = _DEFAULT_TIMEFRAME_MINUTES,
) -> str:
    """
    Hunt for persistence mechanisms: registry Run keys, scheduled task creation,
    startup folder writes, service installation.
    MITRE: T1547 (Boot Autostart), T1053 (Scheduled Task), T1543 (Create/Modify System Process).

    Args:
        ctx: FastMCP context.
        timeframe_minutes: Lookback window.

    Returns:
        JSON with hit count and matching events.
    """
    query = """dataset=xdr_data
| filter (
    (action_registry_key_name contains "\\Run" or action_registry_key_name contains "\\RunOnce")
    or (actor_process_image_name in ("schtasks.exe", "at.exe") and action_process_command_line contains "/create")
    or (action_file_path contains "\\Startup\\" and action_file_type in ("PE", "VBS", "LNK", "PS1"))
    or (actor_process_image_name = "sc.exe" and action_process_command_line contains "create")
)
| fields event_timestamp, host_name, actor_process_image_name, action_registry_key_name, action_file_path, action_process_command_line
| limit 50"""
    try:
        fetcher = await get_fetcher(ctx)
        result = await _run_hunt_query(fetcher, query, timeframe_minutes)
        result["hunt"] = "persistence"
        result["mitre"] = ["T1547", "T1053", "T1543"]
        return create_response(data=result)
    except _PAPI_ERRORS as e:
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"hunt_persistence failed: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def hunt_credential_dumping(
    ctx: Context,
    timeframe_minutes: Annotated[int, Field(description="Lookback in minutes (default 1440 = 24h)", default=_DEFAULT_TIMEFRAME_MINUTES)] = _DEFAULT_TIMEFRAME_MINUTES,
) -> str:
    """
    Hunt for credential dumping: LSASS memory access, Mimikatz patterns,
    NTDS.dit access, SAM registry hive reads, comsvcs.dll MiniDump.
    MITRE: T1003 (OS Credential Dumping).

    Args:
        ctx: FastMCP context.
        timeframe_minutes: Lookback window.

    Returns:
        JSON with hit count and matching events.
    """
    query = """dataset=xdr_data
| filter (
    (action_process_image_name = "lsass.exe" and event_type = ENUM.PROCESS and actor_process_image_name not in ("MsMpEng.exe", "csrss.exe", "wininit.exe"))
    or (actor_process_command_line contains "sekurlsa" or actor_process_command_line contains "logonpasswords")
    or (action_file_path contains "\\system32\\config\\SAM" and event_type = ENUM.FILE)
    or (action_file_path contains "ntds.dit" and event_type = ENUM.FILE)
    or (actor_process_command_line contains "comsvcs" and actor_process_command_line contains "MiniDump")
)
| fields event_timestamp, host_name, actor_process_image_name, actor_process_command_line, action_process_image_name, action_file_path
| limit 50"""
    try:
        fetcher = await get_fetcher(ctx)
        result = await _run_hunt_query(fetcher, query, timeframe_minutes)
        result["hunt"] = "credential_dumping"
        result["mitre"] = ["T1003", "T1003.001", "T1003.002"]
        return create_response(data=result)
    except _PAPI_ERRORS as e:
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"hunt_credential_dumping failed: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def hunt_suspicious_powershell(
    ctx: Context,
    timeframe_minutes: Annotated[int, Field(description="Lookback in minutes (default 1440 = 24h)", default=_DEFAULT_TIMEFRAME_MINUTES)] = _DEFAULT_TIMEFRAME_MINUTES,
) -> str:
    """
    Hunt for suspicious PowerShell usage: encoded commands (-enc/-EncodedCommand),
    download cradles (IEX, Invoke-WebRequest, DownloadString),
    bypass execution policy, AMSI bypass attempts.
    MITRE: T1059.001 (PowerShell), T1027 (Obfuscated Files).

    Args:
        ctx: FastMCP context.
        timeframe_minutes: Lookback window.

    Returns:
        JSON with hit count and matching events.
    """
    query = """dataset=xdr_data
| filter actor_process_image_name in ("powershell.exe", "pwsh.exe")
    and (
        actor_process_command_line contains "-enc"
        or actor_process_command_line contains "-EncodedCommand"
        or actor_process_command_line contains "IEX"
        or actor_process_command_line contains "Invoke-Expression"
        or actor_process_command_line contains "DownloadString"
        or actor_process_command_line contains "Invoke-WebRequest"
        or actor_process_command_line contains "-Bypass"
        or actor_process_command_line contains "AmsiUtils"
        or actor_process_command_line contains "bypass"
        or actor_process_command_line contains "hidden"
    )
| fields event_timestamp, host_name, actor_process_image_name, actor_process_command_line, actor_process_image_sha256
| limit 50"""
    try:
        fetcher = await get_fetcher(ctx)
        result = await _run_hunt_query(fetcher, query, timeframe_minutes)
        result["hunt"] = "suspicious_powershell"
        result["mitre"] = ["T1059.001", "T1027"]
        return create_response(data=result)
    except _PAPI_ERRORS as e:
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"hunt_suspicious_powershell failed: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def hunt_living_off_the_land(
    ctx: Context,
    timeframe_minutes: Annotated[int, Field(description="Lookback in minutes (default 1440 = 24h)", default=_DEFAULT_TIMEFRAME_MINUTES)] = _DEFAULT_TIMEFRAME_MINUTES,
) -> str:
    """
    Hunt for Living-off-the-Land (LOLBin) abuse: certutil, mshta, wscript,
    regsvr32, rundll32, msiexec used to download or execute unusual payloads.
    MITRE: T1218 (Signed Binary Proxy Execution), T1105 (Ingress Tool Transfer).

    Args:
        ctx: FastMCP context.
        timeframe_minutes: Lookback window.

    Returns:
        JSON with hit count and matching events.
    """
    query = """dataset=xdr_data
| filter (
    (actor_process_image_name = "certutil.exe" and (actor_process_command_line contains "-urlcache" or actor_process_command_line contains "-decode"))
    or (actor_process_image_name = "mshta.exe" and (actor_process_command_line contains "http" or actor_process_command_line contains "vbscript"))
    or (actor_process_image_name in ("wscript.exe", "cscript.exe") and action_process_image_name not in ("conhost.exe"))
    or (actor_process_image_name = "regsvr32.exe" and actor_process_command_line contains "/s" and actor_process_command_line contains "http")
    or (actor_process_image_name = "rundll32.exe" and (actor_process_command_line contains "javascript" or actor_process_command_line contains ",EntryPoint"))
    or (actor_process_image_name = "msiexec.exe" and actor_process_command_line contains "http")
)
| fields event_timestamp, host_name, actor_process_image_name, actor_process_command_line, action_remote_ip
| limit 50"""
    try:
        fetcher = await get_fetcher(ctx)
        result = await _run_hunt_query(fetcher, query, timeframe_minutes)
        result["hunt"] = "living_off_the_land"
        result["mitre"] = ["T1218", "T1105", "T1218.005", "T1218.010", "T1218.011"]
        return create_response(data=result)
    except _PAPI_ERRORS as e:
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"hunt_living_off_the_land failed: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def hunt_data_exfiltration(
    ctx: Context,
    timeframe_minutes: Annotated[int, Field(description="Lookback in minutes (default 1440 = 24h)", default=_DEFAULT_TIMEFRAME_MINUTES)] = _DEFAULT_TIMEFRAME_MINUTES,
) -> str:
    """
    Hunt for data exfiltration indicators: large outbound network transfers,
    cloud upload tools (rclone, MEGAcmd), unusual DNS volume, compression of
    sensitive paths before network activity.
    MITRE: T1048 (Exfiltration Over Alternative Protocol), T1567 (Exfiltration Over Web Service).

    Args:
        ctx: FastMCP context.
        timeframe_minutes: Lookback window.

    Returns:
        JSON with hit count and matching events.
    """
    query = """dataset=xdr_data
| filter (
    (actor_process_image_name in ("rclone.exe", "megacmd.exe", "mega-cmd.exe") and event_type = ENUM.NETWORK)
    or (event_type = ENUM.NETWORK and action_network_total_counters_bytes_uploaded > 50000000)
    or (actor_process_image_name in ("7z.exe", "rar.exe", "winrar.exe") and action_file_path contains "\\Users\\")
    or (actor_process_image_name = "ftp.exe" and event_type = ENUM.NETWORK)
    or (actor_process_command_line contains "compress" and action_file_extension in ("zip", "rar", "7z", "tar"))
)
| fields event_timestamp, host_name, actor_process_image_name, actor_process_command_line, action_remote_ip, action_network_total_counters_bytes_uploaded
| limit 50"""
    try:
        fetcher = await get_fetcher(ctx)
        result = await _run_hunt_query(fetcher, query, timeframe_minutes)
        result["hunt"] = "data_exfiltration"
        result["mitre"] = ["T1048", "T1567", "T1560"]
        return create_response(data=result)
    except _PAPI_ERRORS as e:
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"hunt_data_exfiltration failed: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def hunt_ransomware_indicators(
    ctx: Context,
    timeframe_minutes: Annotated[int, Field(description="Lookback in minutes (default 1440 = 24h)", default=_DEFAULT_TIMEFRAME_MINUTES)] = _DEFAULT_TIMEFRAME_MINUTES,
) -> str:
    """
    Hunt for ransomware pre-staging and execution indicators: shadow copy deletion
    (vssadmin, wmic), mass file renames/extensions changes, backup deletion,
    bcdedit recovery disable.
    MITRE: T1490 (Inhibit System Recovery), T1486 (Data Encrypted for Impact).

    Args:
        ctx: FastMCP context.
        timeframe_minutes: Lookback window.

    Returns:
        JSON with hit count and matching events.
    """
    query = """dataset=xdr_data
| filter (
    (actor_process_image_name = "vssadmin.exe" and actor_process_command_line contains "delete")
    or (actor_process_image_name = "wmic.exe" and actor_process_command_line contains "shadowcopy" and actor_process_command_line contains "delete")
    or (actor_process_image_name = "bcdedit.exe" and (actor_process_command_line contains "recoveryenabled no" or actor_process_command_line contains "bootstatuspolicy"))
    or (actor_process_image_name = "wbadmin.exe" and actor_process_command_line contains "delete")
    or (event_type = ENUM.FILE and action_file_extension in ("locked", "encrypted", "cry", "crypt", "ryk", "lck"))
)
| fields event_timestamp, host_name, actor_process_image_name, actor_process_command_line, action_file_path, action_file_extension
| limit 50"""
    try:
        fetcher = await get_fetcher(ctx)
        result = await _run_hunt_query(fetcher, query, timeframe_minutes)
        result["hunt"] = "ransomware_indicators"
        result["mitre"] = ["T1490", "T1486", "T1489"]
        return create_response(data=result)
    except _PAPI_ERRORS as e:
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"hunt_ransomware_indicators failed: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def hunt_new_local_accounts(
    ctx: Context,
    timeframe_minutes: Annotated[int, Field(description="Lookback in minutes (default 1440 = 24h)", default=_DEFAULT_TIMEFRAME_MINUTES)] = _DEFAULT_TIMEFRAME_MINUTES,
) -> str:
    """
    Hunt for new local account creation and privilege escalation:
    net user /add, net localgroup administrators /add, new user via PowerShell.
    MITRE: T1136.001 (Create Local Account), T1098 (Account Manipulation).

    Args:
        ctx: FastMCP context.
        timeframe_minutes: Lookback window.

    Returns:
        JSON with hit count and matching events.
    """
    query = """dataset=xdr_data
| filter (
    (actor_process_image_name = "net.exe" and (actor_process_command_line contains "user" and actor_process_command_line contains "/add"))
    or (actor_process_image_name = "net.exe" and actor_process_command_line contains "localgroup" and actor_process_command_line contains "administrators" and actor_process_command_line contains "/add")
    or (actor_process_image_name = "net1.exe" and actor_process_command_line contains "user" and actor_process_command_line contains "/add")
    or (actor_process_command_line contains "New-LocalUser" or actor_process_command_line contains "Add-LocalGroupMember")
)
| fields event_timestamp, host_name, actor_process_image_name, actor_process_command_line, actor_effective_username
| limit 50"""
    try:
        fetcher = await get_fetcher(ctx)
        result = await _run_hunt_query(fetcher, query, timeframe_minutes)
        result["hunt"] = "new_local_accounts"
        result["mitre"] = ["T1136.001", "T1098"]
        return create_response(data=result)
    except _PAPI_ERRORS as e:
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"hunt_new_local_accounts failed: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class ThreatHuntingModule(BaseModule):
    """
    Pre-built XQL threat hunting queries for common attack patterns.

    Tools:
        - hunt_lateral_movement: PsExec, WMI remote, SMB admin shares.
        - hunt_persistence: Registry Run keys, scheduled tasks, startup folder.
        - hunt_credential_dumping: LSASS access, Mimikatz, SAM/NTDS reads.
        - hunt_suspicious_powershell: Encoded commands, download cradles, AMSI bypass.
        - hunt_living_off_the_land: certutil, mshta, regsvr32, msiexec abuse.
        - hunt_data_exfiltration: rclone, large uploads, compression before transfer.
        - hunt_ransomware_indicators: VSS deletion, bcdedit, encrypted file extensions.
        - hunt_new_local_accounts: net user /add, local admin group modification.
    """

    def register_tools(self):
        self._add_tool(hunt_lateral_movement)
        self._add_tool(hunt_persistence)
        self._add_tool(hunt_credential_dumping)
        self._add_tool(hunt_suspicious_powershell)
        self._add_tool(hunt_living_off_the_land)
        self._add_tool(hunt_data_exfiltration)
        self._add_tool(hunt_ransomware_indicators)
        self._add_tool(hunt_new_local_accounts)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
