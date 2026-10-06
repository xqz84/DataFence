"""One-worker Windows/private server with explicit network and TLS configuration."""

import argparse
import json
import ipaddress
import os
from pathlib import Path
import sys


def main():
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=root / "runtime")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--lan", action="store_true")
    parser.add_argument("--bind-address", help="Optional local interface IP; local mode permits only 127.0.0.1")
    parser.add_argument("--allowed-hosts", default="")
    parser.add_argument("--allowed-origins", default="")
    parser.add_argument("--tls-cert", type=Path)
    parser.add_argument("--tls-key", type=Path)
    parser.add_argument("--require-model", help="Refuse to start unless this promoted model is active and valid")
    parser.add_argument("--require-model-sha256", help="Optional required active model artifact SHA-256")
    args = parser.parse_args()
    if args.bind_address:
        try:
            ipaddress.ip_address(args.bind_address)
        except ValueError:
            parser.error("bind-address must be an IP address")
        if not args.lan and args.bind_address != "127.0.0.1":
            parser.error("local mode may bind only 127.0.0.1")
    if not 1024 <= args.port <= 65535:
        parser.error("port must be 1024..65535")
    data = args.data_dir.resolve()
    if args.lan and (not args.tls_cert or not args.tls_key or not args.tls_cert.is_file() or not args.tls_key.is_file()):
        parser.error("LAN deployment requires TLS certificate and private-key PEM files")
    os.environ["DATAFENCE_DATA_DIR"] = str(data)
    os.environ["DATAFENCE_NETWORK_MODE"] = "lan" if args.lan else "local"
    os.environ["DATAFENCE_AUTH_MODE"] = "required"
    os.environ["DATAFENCE_SERVER_PORT"] = str(args.port)
    os.environ["DATAFENCE_ALLOWED_HOSTS"] = args.allowed_hosts
    os.environ["DATAFENCE_ALLOWED_ORIGINS"] = args.allowed_origins
    # Import only after setting runtime/model paths.
    from .deployment import Deployment
    Deployment.load()
    from .model_initialization import initialize_runtime_model, require_runtime_model
    model_setup = initialize_runtime_model(data, root)
    if model_setup["status"] == "initialized":
        print(f"Initialized trained behavior model: {model_setup['model']}", flush=True)
    elif model_setup["status"] in {"source_missing", "existing_without_active"}:
        print("No active trained model is available in this runtime; the detector will use the known legacy baseline. "
              "Existing model directories are not replaced automatically.", file=sys.stderr)
    if args.require_model_sha256 and not args.require_model:
        parser.error("--require-model-sha256 requires --require-model")
    if args.require_model:
        try:
            selected = require_runtime_model(data, args.require_model, args.require_model_sha256)
        except (OSError, ValueError, TypeError, KeyError) as error:
            parser.error(f"required model readiness check failed: {type(error).__name__}")
        print(f"Required model validated: {selected['name']}", flush=True)
    data.mkdir(parents=True, exist_ok=True)
    logs = data / "logs"
    logs.mkdir(exist_ok=True)
    log_config = {
        "version": 1, "disable_existing_loggers": False,
        "formatters": {"standard": {"format": "%(asctime)s %(levelname)s %(name)s %(message)s"}},
        "handlers": {
            "file": {"class": "logging.handlers.RotatingFileHandler", "filename": str(logs / "server.log"),
                     "maxBytes": 5_000_000, "backupCount": 5, "encoding": "utf-8", "formatter": "standard"},
            "console": {"class": "logging.StreamHandler", "stream": "ext://sys.stdout", "formatter": "standard"}},
        "root": {"handlers": ["file", "console"], "level": "INFO"},
        "loggers": {"uvicorn": {"handlers": [], "propagate": True},
                    "uvicorn.error": {"handlers": [], "propagate": True},
                    "uvicorn.access": {"handlers": [], "propagate": True}}}
    import uvicorn
    uvicorn.run("datafence.api:app", host=args.bind_address or ("0.0.0.0" if args.lan else "127.0.0.1"), port=args.port,
                workers=1, proxy_headers=False, server_header=False, limit_concurrency=64,
                timeout_keep_alive=5, timeout_graceful_shutdown=90, log_config=log_config,
                ssl_certfile=str(args.tls_cert.resolve()) if args.lan else None,
                ssl_keyfile=str(args.tls_key.resolve()) if args.lan else None)


if __name__ == "__main__":
    main()
