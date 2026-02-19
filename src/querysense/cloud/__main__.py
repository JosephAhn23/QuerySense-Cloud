"""
Entry point for running QuerySense Cloud directly.

Usage:
    python -m querysense.cloud
    python -m querysense.cloud --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

import argparse
import sys


def main() -> None:
    """Run the QuerySense Cloud server."""
    try:
        import uvicorn
    except ImportError:
        print(
            "QuerySense Cloud requires extra dependencies.\n"
            "Install with: pip install querysense[cloud]",
            file=sys.stderr,
        )
        sys.exit(1)

    parser = argparse.ArgumentParser(description="QuerySense Cloud Server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")
    args = parser.parse_args()

    print(f"Starting QuerySense Cloud on http://{args.host}:{args.port}")
    print(f"  API docs: http://{args.host}:{args.port}/api/docs")
    print(f"  Web UI:   http://{args.host}:{args.port}/")
    print()

    uvicorn.run(
        "querysense.cloud.app:create_app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        factory=True,
    )


if __name__ == "__main__":
    main()
