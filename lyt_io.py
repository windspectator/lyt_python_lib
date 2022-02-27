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
            if line.startswith(start_from):
                started = True
            else:
                continue
        if stop_at is not None and line.startswith(stop_at):
            break
        lines.append(line)
    return lines

# read/save strings line by line in text file.
def load_txt(name, strip=True, start_from=None, stop_at=None):
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

def save_txt(name, data):
    with open(name, 'w', encoding="utf-8") as f:
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
        json.dump(data, f)

def get_path(path):
    from pathlib import Path
    return Path(path).resolve().as_posix()

def get_path_name(path):
    from pathlib import Path
    return Path(path).name

def get_path_stem(path):
    from pathlib import Path
    return Path(path).stem

def get_path_parent(path):
    from pathlib import Path
    return Path(path).resolve().parent.as_posix() + "/"

def get_path_children(path, only_file=False, only_dir=False, recursive=False,
                      only_name=False, pattern=None, filter_func=(lambda _ : True)):
    """
    Do not set recursive when you use a pattern,
    eg. you should pass a pattern like "a/*/c/*.cpp" or "**/*.py"
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

def get_path_subdirs(path):
    from pathlib import Path
    return [x.as_posix() for x in Path(path).resolve().iterdir() if x.is_dir()]

def is_path_exist(path):
    from pathlib import Path
    return Path(path).exists()

def mkdirs(path):
    import os
    os.makedirs(path, exist_ok=True)

def edit_file_by_line(src, func, dst=None):
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
