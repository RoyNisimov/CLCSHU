


class InputException(Exception):
    def __init__(self, message=None, *args):
        if message is None: message = 'Input can be '
        super().__init__(message + '/'.join(args))
class UnauthorisedChange(Exception):
    def __init__(self, message=''):
        super().__init__(message)


