class BWTException(Exception):
    pass


class BWTExpired(BWTException):
    pass


class BWTInvalid(BWTException):
    pass


class BWTNotSupported(BWTException):
    pass
