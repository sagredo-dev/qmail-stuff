import time
import hashlib
import logging
from django.core.cache import cache
from django.http import HttpResponseTooManyRequests


logger = logging.getLogger("mailman_security")


class SimpleRateLimitMiddleware:
    """
    Lightweight rate limiting middleware based on Memcached.

    Protects sensitive endpoints like signup and login
    """

    # Rate limits: path -> (max_requests, window_seconds)
    LIMITS = {
        "/accounts/signup/": (3, 3600),   # 3 requests per hour
        "/accounts/login/": (10, 600),    # 10 requests per 10 minutes
    }

    def __init__(self, get_response):
        self.get_response = get_response

    def _get_client_ip(self, request):
        """
        Extract real client IP considering reverse proxy headers.
        """
        xff = request.META.get("HTTP_X_FORWARDED_FOR")
        if xff:
            return xff.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR")

    def _cache_key(self, path, ip):
        """
        Generate a stable cache key for rate limiting.
        """
        raw = f"{path}:{ip}"
        return "rl:" + hashlib.md5(raw.encode()).hexdigest()

    def __call__(self, request):

        path = request.path_info

        # Only apply rate limiting on configured endpoints
        if path not in self.LIMITS:
            return self.get_response(request)

        limit, window = self.LIMITS[path]
        ip = self._get_client_ip(request)

        key = self._cache_key(path, ip)

        data = cache.get(key)
        now = int(time.time())

        # First request in window
        if data is None:
            cache.set(key, {"count": 1, "start": now}, timeout=window)
            return self.get_response(request)

        # Reset window if expired
        if now - data["start"] > window:
            cache.set(key, {"count": 1, "start": now}, timeout=window)
            return self.get_response(request)

        # Increment request counter
        data["count"] += 1
        cache.set(key, data, timeout=window)

        # Block if limit exceeded
        if data["count"] > limit:

            logger.warning(
                "RATE_LIMIT_EXCEEDED path=%s ip=%s count=%s",
                path, ip, data["count"]
            )

            return HttpResponseTooManyRequests(
                "Too many requests. Please try again later."
            )

        return self.get_response(request)
