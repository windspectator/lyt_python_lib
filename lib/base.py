import sys
assert sys.version_info[0] >= 3 and sys.version_info[1] >= 7, \
    "need to be run under python 3.7+"
is_windows = (sys.platform == "win32")     # windows or linux(android)
platform = "linux"
if is_windows:
    platform = "windows"

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
