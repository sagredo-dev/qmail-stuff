from allauth.account.forms import SignupForm, LoginForm
from hcaptcha.fields import hCaptchaField


class CaptchaSignupForm(SignupForm):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['captcha'] = hCaptchaField()


class CaptchaLoginForm(LoginForm):

    MAX_FAILS = 2

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        fails = 0
        if hasattr(self, "request"):
            fails = self.request.session.get("login_fail_count", 0)

        if fails >= self.MAX_FAILS:
            self.fields['captcha'] = hCaptchaField()
