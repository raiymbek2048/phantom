"""
Rate Limiter — controls outgoing request rate to avoid IP bans.
"""
import asyncio
import time


class RateLimiter:
    def __init__(self, max_per_second: int = 10):
        self.max_per_second = max_per_second
        self.semaphore = asyncio.Semaphore(max_per_second)
        self.timestamps: list[float] = []
        self.lock = asyncio.Lock()

    async def acquire(self):
        """Wait until we can send another request."""
        async with self.lock:
            now = time.time()
            # Remove timestamps older than 1 second
            self.timestamps = [t for t in self.timestamps if now - t < 1.0]

            if len(self.timestamps) >= self.max_per_second:
                sleep_time = 1.0 - (now - self.timestamps[0])
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)

            self.timestamps.append(time.time())

    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass
