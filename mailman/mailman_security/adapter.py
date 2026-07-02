import logging
from allauth.account.adapter import DefaultAccountAdapter

logger = logging.getLogger("mailman_security")

class SecurityAccountAdapter(DefaultAccountAdapter):
    """
    Custom allauth adapter to track authentication failures.
    """

    def authentication_failed(self, request, **credentials):
        """
        Called whenever login authentication fails.
        """

        ip = self.get_client_ip(request)
        username = credentials.get("username", "unknown")

        logger.warning(
            "LOGIN_FAILED ip=%s username=%s",
            ip,
            username
        )

        return super().authentication_failed(request, **credentials)

    def get_client_ip(self, request):
        """
        Extract real client IP behind reverse proxy.
        """
        xff = request.META.get("HTTP_X_FORWARDED_FOR")
        if xff:
            return xff.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR")
