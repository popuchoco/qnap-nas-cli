class QtsError(Exception):
    """Expected user-facing failure."""


class AuthenticationError(QtsError):
    pass


class CompatibilityError(QtsError):
    pass
