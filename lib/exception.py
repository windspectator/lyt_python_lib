class Timeout_exception(Exception):
    def __init__(
        self, raw_exception = None, output: str = None, error: str = None
    ) -> None:
        super().__init__(raw_exception)
        self.output = output
        self.error = error

class Return_nonzero_exception(Exception):
    def __init__(self, ret: int, output: str = None, error: str = None) -> None:
        super().__init__()
        self.ret = ret
        self.output = output
        self.error = error
