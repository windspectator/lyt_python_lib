import sys
assert sys.version_info[0] >= 3 and sys.version_info[1] >= 7, \
    "need to be run under python 3.7+"
is_windows = (sys.platform == "win32")     # windows or linux(android)
platform = "linux"
if is_windows:
    platform = "windows"

from typing import Union, List, Callable, Tuple, Iterable, Mapping
from types import ModuleType
from lyt_print import *

def try_import(import_name: str, package_name: str = None) -> ModuleType:
    if package_name is None:
        package_name = import_name
    try:
        return __import__(import_name)
    except ModuleNotFoundError:
        pr_info(f"cannot find {import_name}, please install {package_name} "
                "to leverage all features")
        return None

def whoami() -> str:
    import os, pwd
    return pwd.getpwuid(os.getuid())[0]

def i_am_root() -> bool:
    return whoami() == "root"

def set_low_priority() -> None:
    import os
    if is_windows:
        # import psutil
        # p = psutil.Process(os.getpid())
        # p.nice(psutil.IDLE_PRIORITY_CLASS)  # BELOW_NORMAL_PRIORITY_CLASS
        pass
    else:
        os.nice(20)

def get_terminal_size() -> List[int]:
    """
    returns (width, height)
    """
    import os
    try:
        size = os.get_terminal_size()
    except OSError:
        return (80, 24)
    return [size[0], size[1]]

def get_terminal_size_hw() -> List[int]:
    return reversed(get_terminal_size())

def time() -> float:
    import time
    return time.time()

# same as tic/toc in matlab
_timer = 0
def tic() -> None:
    # reset _timer
    global _timer
    _timer = time()

def toc(
    print_time: bool = True, reset_timer: bool = True, return_str: bool = True
) -> Union[float, str]:
    global _timer
    cur_time = time()
    elasped_time = cur_time - _timer

    def get_str(seconds):
        m, s = divmod(seconds, 60)
        s = "{:.2f}".format(s)
        m = int(m)
        if m == 0:
            return f"elasped time is {s} seconds"
        h, m = divmod(m, 60)
        if h == 0:
            return f"elasped time is {m} min {s} seconds"
        d, h = divmod(h, 24)
        if d == 0:
            return f"elasped time is {h}:{m}:{s}"
        return f"elasped time is {d} day {h}:{m}:{s}"

    if reset_timer:
        _timer = cur_time

    elasped_str = get_str(elasped_time)
    if print_time:
        print(elasped_str)

    return elasped_str if return_str else elasped_time

def is_iterable(obj) -> bool:
    try:
        iter(obj)
        return True
    except TypeError:
        return False

class work_in:
    def __init__(self, work_path: str):
        from linux_commands import pwd
        self.old_path = pwd()
        self.new_path = work_path

    def __enter__(self):
        from linux_commands import cd
        cd(self.new_path)

    def __exit__(self, *_):
        from linux_commands import cd
        cd(self.old_path)

def get_cpu_count() -> int:
    import multiprocessing
    return multiprocessing.cpu_count()

def run_multi_process(func: Callable, tasks: List, process_num: int = None) -> List:
    from multiprocessing import Pool
    from lyt_tqdm import tqdm

    if process_num is None:
        process_num = get_cpu_count()
    with Pool(process_num) as pool:
        result = list(tqdm(pool.imap_unordered(func, tasks), total=len(tasks)))
    return result
