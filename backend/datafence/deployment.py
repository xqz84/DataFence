"""Explicit local/LAN deployment boundaries. No implicit remote demo access."""

from dataclasses import dataclass
import os
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Deployment:
    network_mode: str
    auth_mode: str
    hosts: tuple[str, ...]
    origins: tuple[str, ...]
    secure_cookie: bool

    @classmethod
    def load(cls, auth_mode: str | None = None):
        mode = os.environ.get("DATAFENCE_NETWORK_MODE", "local")
        auth = auth_mode or os.environ.get("DATAFENCE_AUTH_MODE", "required")
        if mode not in {"local", "lan"} or auth not in {"required", "local_demo"}:
            raise ValueError("Invalid deployment mode")
        if mode == "lan":
            hosts = tuple(x.strip() for x in os.environ.get("DATAFENCE_ALLOWED_HOSTS", "").split(",") if x.strip())
            origins = tuple(x.strip() for x in os.environ.get("DATAFENCE_ALLOWED_ORIGINS", "").split(",") if x.strip())
            if auth != "required" or not hosts or not origins:
                raise ValueError("LAN requires authentication, explicit hosts and HTTPS origins")
            for host in hosts:
                if any(c in host for c in "/*@?#\\") or len(host) > 253:
                    raise ValueError("LAN host must be an exact hostname or IP")
            for origin in origins:
                parsed = urlsplit(origin)
                if (parsed.scheme != "https" or parsed.hostname not in hosts or parsed.path
                        or parsed.query or parsed.fragment or parsed.username or parsed.password):
                    raise ValueError("LAN origins must be exact HTTPS origins for allowed hosts")
                _ = parsed.port
            return cls(mode, auth, hosts, origins, True)
        return cls(mode, auth, ("127.0.0.1", "localhost", "[::1]"), (), False)

    def origin_allowed(self, origin: str) -> bool:
        try:
            parsed = urlsplit(origin)
            _ = parsed.port
            if self.network_mode == "lan":
                return origin in self.origins
            return (parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
                    and not parsed.username and not parsed.password and not parsed.path
                    and not parsed.query and not parsed.fragment)
        except ValueError:
            return False
