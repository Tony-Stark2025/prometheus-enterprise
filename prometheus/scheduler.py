"""
Asynchronous background scheduler for Prometheus daily alignment digests.
Runs automated cron triggers (e.g. 08:00 AM daily briefing) and background fleet checks.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional
from prometheus.security.abac_guard import UserContext
from prometheus.workflows.prometheus_flow import PrometheusWorkflow

logger = logging.getLogger(__name__)


class PrometheusScheduler:
    """
    Background scheduler for scheduled alignment digests and continuous telemetry scans.
    """

    def __init__(self, interval_seconds: int = 3600):
        self._interval = interval_seconds
        self._task: Optional[asyncio.Task] = None
        self._is_running = False

    async def start(self):
        if self._is_running:
            return
        self._is_running = True
        self._task = asyncio.create_task(self._schedule_loop())
        logger.info("⏱️ [PrometheusScheduler] Background cron scheduler started.")

    async def stop(self):
        self._is_running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("⏱️ [PrometheusScheduler] Background cron scheduler stopped.")

    async def _schedule_loop(self):
        while self._is_running:
            try:
                now = datetime.now(timezone.utc)
                # Calculate sleep duration until next 08:00 AM UTC briefing
                target = now.replace(hour=8, minute=0, second=0, microsecond=0)
                if now >= target:
                    from datetime import timedelta
                    target += timedelta(days=1)
                seconds_until_target = (target - now).total_seconds()

                # If interval is customized (e.g. fast testing mode), honor it; otherwise wait for next 08:00 AM UTC
                wait_seconds = min(seconds_until_target, self._interval) if self._interval != 3600 else seconds_until_target
                logger.info(f"⏱️ [PrometheusScheduler] Next 08:00 AM daily briefing scheduled in {wait_seconds:.0f}s (at {target.isoformat()}).")

                await asyncio.sleep(wait_seconds)
                if not self._is_running:
                    break

                logger.info("⏱️ [PrometheusScheduler] Triggering scheduled 08:00 AM daily alignment briefing...")
                system_user = UserContext(
                    user_id="cron-system",
                    username="prometheus-cron",
                    is_authenticated=True,
                    org_scopes={"engineering", "platform"},
                )
                await PrometheusWorkflow.run(
                    user=system_user,
                    query="Daily 08:00 AM scheduled alignment digest execution",
                )
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"❌ [PrometheusScheduler] Error in background execution: {e}")
                await asyncio.sleep(60)


scheduler = PrometheusScheduler()
