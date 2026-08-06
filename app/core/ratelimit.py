"""Rate limiting rahisi ya ndani ya process moja.

Inatosha kwa server moja ya development au deploy ndogo. Ukienda kwenye
workers wengi au mashine nyingi, ibadilishe iwe Redis, interface ni ile ile.

Hakuna thread lock: FastAPI inaendesha kwenye event loop moja, na kila
`hit()` ni synchronous, hivyo hakuna nafasi ya kukatizwa katikati.
"""

import time
from collections import defaultdict, deque

from app.core.errors import AppError


class RateLimitError(AppError):
    status_code = 429
    code = "rate_limited"


class SlidingWindowLimiter:
    def __init__(self, *, limit: int, window_seconds: int) -> None:
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def hit(self, key: str) -> None:
        """Inarusha `RateLimitError` ikiwa kikomo kimezidi."""
        now = time.monotonic()
        bucket = self._hits[key]

        cutoff = now - self.window
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

        if len(bucket) >= self.limit:
            retry_after = int(bucket[0] + self.window - now) + 1
            raise RateLimitError(
                f"Too many attempts. Try again in {retry_after} seconds.",
            )

        bucket.append(now)

        # Keys zisizotumika tena zisijae kwenye memory.
        if len(self._hits) > 10_000:
            self._prune(cutoff)

    def _prune(self, cutoff: float) -> None:
        stale = [key for key, hits in self._hits.items() if not hits or hits[-1] <= cutoff]
        for key in stale:
            del self._hits[key]

    def reset(self) -> None:
        """Kwa tests."""
        self._hits.clear()


#: `/auth/session` inaitwa mara moja kwa login. 10 kwa dakika kwa IP ni
#: nafuu kwa matumizi halali na inabana majaribio ya kupiga token nyingi.
session_limiter = SlidingWindowLimiter(limit=10, window_seconds=60)

#: Password reset ni ya thamani kubwa kwa mshambuliaji: inatuma email na
#: inakubali kubahatisha OTP. Inabanwa zaidi.
otp_limiter = SlidingWindowLimiter(limit=6, window_seconds=300)

#: Kualika watu kunatuma email kwenda anwani yoyote, hivyo ni njia ya
#: kutumia server yetu kutuma spam ikiachwa wazi.
invite_limiter = SlidingWindowLimiter(limit=20, window_seconds=3600)


def client_key(client_host: str | None) -> str:
    return client_host or "unknown"
