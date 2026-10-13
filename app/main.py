"""
Entrypoint shim for `app/main.py` (`uvicorn app.main:app` and `python app/main.py --cli`).
Delegates directly to the canonical `prometheus.main` module.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prometheus.main import *  # noqa: F401,F403
from prometheus.main import app, cli_runner, settings

if __name__ == "__main__":
    import asyncio
    if len(sys.argv) > 1 and sys.argv[1] in ("--cli", "-c"):
        asyncio.run(cli_runner())
    else:
        import uvicorn
        uvicorn.run("prometheus.main:app", host=settings.host, port=settings.port, reload=True)
