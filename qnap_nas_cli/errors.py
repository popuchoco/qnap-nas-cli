class QtsError(Exception):
    """Expected user-facing failure."""


class AuthenticationError(QtsError):
    pass


class TwoFactorRequired(AuthenticationError):
    """The password phase succeeded but QTS requires a second factor."""


class CompatibilityError(QtsError):
    pass
