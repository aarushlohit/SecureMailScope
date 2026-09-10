"""
SecureMailScope - System Tool Discovery & Safe Execution Wrappers
Strictly manages execution of external binaries (tshark, capinfos, zeek, openssl)
with allowlisted arguments, explicit timeouts, and zero shell execution.
"""
import shutil
import subprocess
import os
import re
from pathlib import Path
from typing import Dict, Any, Optional, List
from securemailscope.core.config import config


class SystemToolDiscovery:
    """Discovers installed system binaries and extracts real versions."""

    @classmethod
    def get_binary_path(cls, binary_name: str, config_override: Optional[str] = None) -> Optional[str]:
        if config_override and Path(config_override).exists():
            return config_override
        return shutil.which(binary_name)

    @classmethod
    def inspect_tool(cls, tool_name: str) -> Dict[str, Any]:
        """
        Check if a tool is installed, return real path, version, and health status.
        """
        binary_map = {
            "tshark": (config.tshark_path, ["-v"]),
            "capinfos": (config.capinfos_path, ["-v"]),
            "zeek": (config.zeek_path, ["--version"]),
            "openssl": (config.openssl_path, ["version"])
        }

        if tool_name not in binary_map:
            return {
                "name": tool_name,
                "installed": False,
                "version": "UNKNOWN",
                "path": None,
                "healthy": False,
                "error": f"Tool '{tool_name}' is not in system tool catalogue."
            }

        override, ver_args = binary_map[tool_name]
        bin_path = cls.get_binary_path(tool_name, override)

        if not bin_path:
            return {
                "name": tool_name,
                "installed": False,
                "version": "UNAVAILABLE",
                "path": None,
                "healthy": False,
                "error": f"Binary '{tool_name}' not found on system PATH."
            }

        try:
            res = subprocess.run(
                [bin_path] + ver_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
                shell=False
            )
            out = (res.stdout or res.stderr).strip().splitlines()
            version_str = out[0] if out else "DETECTED"
            return {
                "name": tool_name,
                "installed": True,
                "version": version_str,
                "path": bin_path,
                "healthy": res.returncode == 0
            }
        except subprocess.TimeoutExpired:
            return {
                "name": tool_name,
                "installed": True,
                "version": "TIMEOUT",
                "path": bin_path,
                "healthy": False,
                "error": "Version check timed out."
            }
        except Exception as e:
            return {
                "name": tool_name,
                "installed": True,
                "version": "ERROR",
                "path": bin_path,
                "healthy": False,
                "error": str(e)
            }

    @classmethod
    def discover_all(cls) -> Dict[str, Any]:
        tools = ["tshark", "capinfos", "zeek", "openssl"]
        return {t: cls.inspect_tool(t) for t in tools}


class SafeBinaryRunner:
    """Executes allowlisted system binaries safely with timeout and argument filtering."""

    @classmethod
    def run_capinfos(cls, pcap_path: str) -> Dict[str, Any]:
        info = SystemToolDiscovery.inspect_tool("capinfos")
        if not info["installed"]:
            return {"status": "UNAVAILABLE", "error": "capinfos is not installed."}

        pcap = Path(pcap_path).resolve()
        if not pcap.exists() or not pcap.is_file():
            return {"status": "ERROR", "error": f"PCAP file not found: {pcap_path}"}

        try:
            # -T: machine readable table; -m: human readable; -c: packet count; -u: capture duration
            cmd = [info["path"], "-c", "-u", "-d", "-s", str(pcap)]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15, shell=False)
            if res.returncode != 0:
                return {"status": "ERROR", "error": res.stderr}

            output = res.stdout
            parsed = {}
            for line in output.splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    parsed[k.strip().lower().replace(" ", "_")] = v.strip()
            return {"status": "SUCCESS", "data": parsed, "raw": output}
        except Exception as e:
            return {"status": "ERROR", "error": str(e)}

    @classmethod
    def run_tshark_fields(cls, pcap_path: str, display_filter: str, fields: List[str]) -> Dict[str, Any]:
        info = SystemToolDiscovery.inspect_tool("tshark")
        if not info["installed"]:
            return {"status": "UNAVAILABLE", "error": "tshark is not installed."}

        pcap = Path(pcap_path).resolve()
        if not pcap.exists() or not pcap.is_file():
            return {"status": "ERROR", "error": f"PCAP file not found: {pcap_path}"}

        cmd = [info["path"], "-r", str(pcap), "-Y", display_filter, "-T", "fields"]
        for f in fields:
            # Allow only valid alphanumeric and dot/underscore field names
            if re.match(r"^[a-zA-Z0-9_\.\-]+$", f):
                cmd.extend(["-e", f])

        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20, shell=False)
            if res.returncode != 0:
                return {"status": "ERROR", "error": res.stderr}
            rows = [line.split("\t") for line in res.stdout.splitlines() if line.strip()]
            return {"status": "SUCCESS", "rows": rows, "count": len(rows)}
        except Exception as e:
            return {"status": "ERROR", "error": str(e)}

    @classmethod
    def run_openssl_x509(cls, cert_pem_or_der_path: str) -> Dict[str, Any]:
        info = SystemToolDiscovery.inspect_tool("openssl")
        if not info["installed"]:
            return {"status": "UNAVAILABLE", "error": "openssl is not installed."}

        path = Path(cert_pem_or_der_path).resolve()
        if not path.exists():
            return {"status": "ERROR", "error": f"Certificate file not found: {cert_pem_or_der_path}"}

        try:
            cmd = [info["path"], "x509", "-in", str(path), "-text", "-noout"]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10, shell=False)
            if res.returncode != 0:
                return {"status": "ERROR", "error": res.stderr}
            return {"status": "SUCCESS", "text": res.stdout}
        except Exception as e:
            return {"status": "ERROR", "error": str(e)}
