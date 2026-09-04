"""Standalone TrustPulse telemetry worker entrypoint.

Run with:
    python -m app.workers.telemetry_worker_main
"""

import asyncio
import signal

from app.core.logging import logger, setup_logging
from app.workers.telemetry_worker import TelemetryWorker

setup_logging()


async def main() -> None:
    worker = TelemetryWorker()
    stop = asyncio.Event()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    await worker.start()
    logger.info("Telemetry worker running. Press Ctrl+C to stop.")
    await stop.wait()
    await worker.stop()
    logger.info("Telemetry worker stopped.")


if __name__ == "__main__":
    asyncio.run(main())
