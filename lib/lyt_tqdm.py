from base import *

class lyt_tqdm():
    def __init__(self, iterable: Iterable = None):
        self.iterator = None if iterable is None else iter(iterable)
        len_func = getattr(iterable, "__len__", None)
        self.task_len = len_func() if callable(len_func) else None
        self.task_done = 0

    def print_progress_bar(self):
        if self.task_len is None:
            print("\r", f"{self.task_done} its", end="\r")
            return
        # at least minus 10 here to leave enough space
        bar_len = get_terminal_size()[0] - 15
        progress = self.task_done / self.task_len

        if bar_len <= 0:
            text = ""
        else:
            progress_len = int(bar_len * progress)
            text = '[' + '|' * progress_len + '-' * (bar_len - progress_len) + ']'
        import sys
        print('\r', text, "{0:.1%}".format(progress), end='\r', file=sys.stderr)
        if (self.task_done == self.task_len):
            print()

    def __iter__(self):
        return self
    
    def update(self, num):
        self.task_done += num
        self.print_progress_bar()

    def __next__(self):
        next_item = next(self.iterator) if self.iterator else None
        self.task_done += 1
        self.print_progress_bar()
        return next_item
    
    def close(self):
        print()

def tqdm(iterable: Iterable=None, *args, **kargs) -> Iterable:
    tqdm_module = try_import("tqdm", "tqdm")
    if tqdm_module is None:
        return lyt_tqdm(iterable)
    return tqdm_module.tqdm(iterable, *args, **kargs)
