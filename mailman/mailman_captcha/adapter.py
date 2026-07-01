from allauth.account.adapter import DefaultAccountAdapter


class CaptchaAccountAdapter(DefaultAccountAdapter):

    def authentication_failed(self, request, **credentials):
        count = request.session.get("login_fail_count", 0)
        request.session["login_fail_count"] = count + 1

    def login(self, request, user):
        request.session["login_fail_count"] = 0
        return super().login(request, user)
