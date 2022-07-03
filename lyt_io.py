from typing import List, Callable, Union

def get_temp_dir() -> str:
    """
    this function will create folder for you
    """
    import lyt_sys
    import lyt_utils
    dir = f"/tmp/{lyt_sys.get_pid()}/"
    lyt_utils.mkdir(dir)
    return dir

def get_temp_path(name: str = None) -> str:
    """
    this function will create folder for you
    """
    import lyt_utils
    f_name = lyt_utils.get_caller_name()
    if name:
        f_name += f"__{name}"
    return get_temp_dir() + f_name

class temp_file:
    def __init__(self, data: Union[List[str], str], name: str = None):
        self.f_path = get_temp_path(type(self).__name__)
        save_txt(self.f_path, data)

    def __enter__(self):
        return self.f_path

    def __exit__(self, *_):
        import lyt_utils
        lyt_utils.rm(self.f_path, quiet=True)

class temp_file_remote:
    def __init__(self, remote_path: str, name: str = None):
        import lyt_utils
        self.f_path = get_temp_path(type(self).__name__)
        lyt_utils.scp(remote_path, self.f_path, return_all=True)
    
    def clean(self):
        import lyt_utils
        lyt_utils.rm(self.f_path, quiet=True)

    def __enter__(self):
        return self.f_path

    def __exit__(self, *_):
        self.clean()

# same as save/load in matlab
def save(name, data):
    import pickle
    pickle.dump(data, open(name, "wb"))

def load(name, encoding="ASCII"):
    import pickle
    return pickle.load(open(name, "rb"), encoding=encoding)

def __load_txt(file, start_from=None, stop_at=None):
    lines = []
    started = True if start_from is None else False
    for line in file:
        if not started:
            if start_from in line:
                started = True
            else:
                continue
        if stop_at is not None and stop_at in line:
            break
        lines.append(line)
    return lines

def _load_txt(
        name: str, strip: bool = True, start_from: str = None, stop_at: str = None
    ) -> List[str]:
    with open(name, encoding="utf-8") as f:
        if start_from is None and stop_at is None:
            lines = f.readlines()
        else:
            lines = __load_txt(f, start_from, stop_at)
    if strip:
        lines = [x.strip() for x in lines]
    else:
        lines = [x[:-1] if x[-1] == "\n" else x for x in lines]
    return lines

# load/save strings line by line in text file.
def load_txt(
        name: str, remote: bool = False,
        strip: bool = True, start_from: str = None, stop_at: str = None
    ) -> List[str]:
    if not remote:
        return _load_txt(name, strip=strip, start_from=start_from, stop_at=stop_at)

    with temp_file_remote(name) as fname:
        return _load_txt(fname, strip=strip, start_from=start_from, stop_at=stop_at)

def save_txt(name: str, data: Union[List[str], str]):
    with open(name, 'w', encoding="utf-8") as f:
        if type(data) is str:
            f.write(data)
            return

        for d in data:
            f.write(d)
            f.write('\n')

def load_json(name):
    import json
    with open(name, 'r', encoding="utf-8") as f:
        return json.load(f)

def save_json(name, data):
    import json
    with open(name, 'w', encoding="utf-8") as f:
        json.dump(data, f, indent=4, sort_keys=True)

def load_csv(name, delimiter=","):
    data = load_txt(name)
    return [x.split(delimiter) for x in data]

def format_folder(path):
    if not path.endswith("/"):
        path = path + "/"
    return path

def is_dir(path):
    from pathlib import Path
    return Path(path).resolve().is_dir()

def get_path(path):
    from pathlib import Path
    return Path(path).resolve().as_posix()

def get_path_name(path):
    from pathlib import Path
    return Path(path).name

def get_path_stem(path):
    from pathlib import Path
    return Path(path).stem

def get_path_parent(path, repeat=1):
    from pathlib import Path
    path = Path(path).resolve()
    for _ in range(repeat):
        path = path.parent
    return format_folder(path.as_posix())

def get_path_children(
        path: str,
        only_file: bool = False, only_dir: bool = False, recursive: bool = False,
        only_name: bool = False, pattern: str = None,
        filter_func: Callable[[str], bool] = (lambda _ : True)
    ) -> List[str]:
    """
    Do not set recursive when you use a pattern,
    eg. you should pass a pattern like "a\*\c\*.cpp" or "**\*.py" (ignore slash directions)

    @only_name: return name but not full path
    """
    from pathlib import Path
    path = Path(path).resolve()
    result = []

    if only_name:
        def _path2str(path):
            return path.name
    else:
        def _path2str(path):
            return path.as_posix()
    if pattern is None:
        def _path_iterate(path):
            return path.iterdir()
    else:
        def _path_iterate(path):
            return path.glob(pattern)

    if not recursive:
        for p in _path_iterate(path):
            if not filter_func(p):
                continue
            if only_file and p.is_dir():
                continue
            if only_dir and not p.is_dir():
                continue
            result.append(_path2str(p))
        return result

    def _get_path_children_recursive(result, cur_path):
        for p in cur_path.iterdir():
            if not p.is_dir():
                if not filter_func(p):
                    continue
                if not only_dir:
                    result.append(_path2str(p))
                continue

            # p is dir
            if not only_file:
                result.append(_path2str(p))
            _get_path_children_recursive(result, p)
        
        return result
    
    return _get_path_children_recursive(result, path)

def get_path_subdirs(path, **kwargs):
    return get_path_children(path, only_dir=True, **kwargs)

def get_path_subfiles(path, **kwargs):
    return get_path_children(path, only_file=True, **kwargs)

def is_path_exist_remote(path: str):
    import lyt_utils
    ip, remote_path = path.split(":", maxsplit=1)
    try:
        lyt_utils.run_remote(
            ip, f"test -f {remote_path}", print_command=False, return_all=True
        )
        return True
    except lyt_utils.Return_nonzero_exception:
        return False

def is_path_exist(path: str, remote: bool = False):
    if remote:
        return is_path_exist_remote(path)

    from pathlib import Path
    return Path(path).exists()

def assert_path_exist(path):
    if not is_path_exist(path):
        raise FileNotFoundError()

def mkdirs(path, exist_ok=True):
    """
    deprecated!
    """
    import os
    os.makedirs(path, exist_ok=exist_ok)

def edit_file_by_line(src: str, func: Callable, dst: str = None) -> int:
    if dst is None:
        dst = src

    src_lines = load_txt(src, strip=False)
    dst_lines = []
    for line in src_lines:
        new_line = func(line)
        if new_line is None:
            continue
        if type(new_line) is str:
            dst_lines.append(new_line)
        else:
            dst_lines.extend(new_line)
    save_txt(dst, dst_lines)
    return len(dst_lines) - len(src_lines)

def edit_file_by_line_remote(vm_ip, src, func, dst=None):
    if dst is None:
        dst = src
    tmp_root = "/home/liuyuntao/temp/"
    tmp_src = tmp_root + "tmp_src"
    tmp_dst = tmp_root + "tmp_dst"
    mkdirs(tmp_root)

    import lyt_utils
    lyt_utils.run(f"scp {vm_ip}:{src} {tmp_src}")
    edit_file_by_line(tmp_src, func, dst=tmp_dst)
    lyt_utils.run(f"scp {tmp_dst} {vm_ip}:{dst}")
