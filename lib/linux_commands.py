from run import *

def cd(path: str) -> None:
    import os
    os.chdir(path)

def pwd() -> str:
    import os, lyt_io
    return lyt_io.format_folder(os.getcwd())

def cp(src: str, dest: str) -> None:
    run(["cp", "-r", src, dest])

def mkdir(
    path: str, exist_ok: bool = True, tmpfs: bool = False, size: int = 128
) -> None:
    """
    this function can create multiple-level folders
    """
    import os
    os.makedirs(path, exist_ok=exist_ok)
    if tmpfs:
        import lyt_io
        assert len(lyt_io.get_path_children(path)) == 0
        # run(["mount", "-t", "tmpfs", "-o", f"size={size}g", "lyt_temp", path])
        run_sudo(f"mount -t tmpfs -o size={size}g lyt_temp {path}")

def rm_one(
    path: str, quiet: bool = False, not_exist_ok: bool = False, tmpfs: bool = False
) -> None:
    import lyt_io
    if not lyt_io.is_path_exist:
        assert not_exist_ok
        return

    if tmpfs:
        run_sudo(f"umount -l {path}")
        run(["rm", "-rf", path], print_command=not quiet)
        return

    try:
        run(["rm", "-rf", path], print_command=not quiet)
    except Return_nonzero_exception:
        rm_one(path, quiet=quiet, not_exist_ok=not_exist_ok, tmpfs=True)

def rm(
    path: Union[str, List[str]], quiet: bool = False, not_exist_ok: bool = False,
    tmpfs: bool = False
) -> None:
    if type(path) is str:
        rm_one(path, quiet=quiet, not_exist_ok=not_exist_ok, tmpfs=tmpfs)
        return

    for p in path:
        rm_one(p, quiet=quiet, not_exist_ok=not_exist_ok, tmpfs=tmpfs)

def mv(src: str, dest: str, tmpfs: bool=False) -> None:
    import lyt_io, shutil
    if lyt_io.is_path_exist(dest):
        dest = lyt_io.format_folder(dest) + lyt_io.get_path_name(src)

    if not tmpfs:
        shutil.move(src, dest)
        return

    assert lyt_io.is_dir(src)
    mkdir(dest, tmpfs=True)
    for child in lyt_io.get_path_children(src):
        mv(child, dest)
    rm(src)

def echo(content: any, dest: str) -> None:
    if type(content) is not str:
        content = str(content)
    run(f"echo {content} > {dest}", shell=True)
