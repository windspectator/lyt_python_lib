from typing import Union, List, Callable, Tuple, Iterable, Mapping
from types import ModuleType
import sys
assert sys.version_info[0] >= 3 and sys.version_info[1] >= 7, "need to be run under python 3.7+"
is_windows = (sys.platform == "win32")     # windows or linux(android)
platform = "linux"
if is_windows:
    platform = "windows"

class Timeout_exception(Exception):
    def __init__(self, raw_exception, output: str = None, error: str = None) -> None:
        super().__init__(raw_exception)
        self.output = output
        self.error = error

class Return_nonzero_exception(Exception):
    def __init__(self, ret: int, output: str = None, error: str = None) -> None:
        super().__init__()
        self.ret = ret
        self.output = output
        self.error = error

def dye(string: str, color: str = "violet") -> str:
    color_list = {
        "violet": "8700A8",
        "red": "A31515",
        "orange": "D75F00",
        "green": "22855C",
        "black": "000000",
        "brown": "8B573A",
    }
    color_code = color_list[color]
    r, g, b = [int(color_code[i:i + 2], 16) for i in range(0, 6, 2)]
    COLOR = f"\033[38;2;{r};{g};{b}m"
    ORIGIN = "\033[0m"

    return (COLOR + string + ORIGIN)

def print_in_color(
    string: str, color: str = "violet", prefix: str = "", suffix: str = ""
) -> None:
    if type(string) is list:
        string = " ".join(string)

    print(prefix + dye(string, color=color) + suffix)

def pr_error(string: str, prefix: str = "", suffix: str = "") -> None:
    print_in_color(string, color="red", prefix=prefix, suffix=suffix)

def pr_warn(string: str, prefix: str = "", suffix: str = "") -> None:
    print_in_color(string, color="orange", prefix=prefix, suffix=suffix)

def pr_notice(string: str, prefix: str = "", suffix: str = "") -> None:
    print_in_color(string, color="violet", prefix=prefix, suffix=suffix)

def pr_info(string: str, prefix: str = "", suffix: str = "") -> None:
    print_in_color(string, color="green", prefix=prefix, suffix=suffix)

def pr_debug(string: str, prefix: str = "", suffix: str = "") -> None:
    print_in_color(string, color="black", prefix=prefix, suffix=suffix)

def pr_command(command: str) -> None:
    pr_notice(command, prefix="-----> ", suffix=" <-----")

def try_import(import_name: str, package_name: str = None) -> ModuleType:
    if package_name is None:
        package_name = import_name
    try:
        return __import__(import_name)
    except ModuleNotFoundError:
        pr_info(f"cannot find {import_name}, please install {package_name} "
                "to leverage all features")
        return None

def get_terminal_size() -> Tuple[int, int]:
    """
    returns (width, height)
    """
    import os
    size = os.get_terminal_size()
    return (size[0], size[1])

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

def tqdm(iterable: Iterable=None, *args, **kargs) -> Iterable:
    tqdm_module = try_import("tqdm", "tqdm")
    if tqdm_module is None:
        return lyt_tqdm(iterable)
    return tqdm_module.tqdm(iterable, *args, **kargs)        

def bytes_to_human(byte_num: int) -> str:
    if byte_num < 1024:
        return f"{byte_num} B"
    unit_list = ["KB", "MB", "GB", "TB"]
    unit_num = byte_num
    for unit in unit_list:
        unit_num /= 1024
        if unit_num < 1024:
            return "{:.2f} {}".format(unit_num, unit)
    return "{:.2f} {}".format(unit_num, unit_list[-1])

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
            return f"elasped time is {m}:{s}"
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

def sleep(sec: float) -> None:
    """
    @sec: sleep time in seconds, can be a float number
    """
    import time
    time.sleep(sec)

def set_low_priority() -> None:
    import os
    if is_windows:
        # import psutil
        # p = psutil.Process(os.getpid())
        # p.nice(psutil.IDLE_PRIORITY_CLASS)  # BELOW_NORMAL_PRIORITY_CLASS
        pass
    else:
        os.nice(20)

def _run_print_when_return(
    command: List[str], input: List[str], return_error: bool,
    check_result: bool, strip: bool
) -> Union[None, List[str], Tuple[List[str], List[str]]]:
    """
    Warning: this function may hang when wait() for subprocess to finish.

    this function will print output in real time and return it finally.
    """
    import subprocess
    p = subprocess.Popen(
        command,
        stdin=(subprocess.PIPE if input else None),
        stdout=subprocess.PIPE,
        stderr=(subprocess.PIPE if return_error else None),
        text=True,
    )

    if input:
        p.stdin.write(input)
        p.stdin.flush()

    output = []
    error = []

    for line in p.stdout:
        print(line[:-1] if line.endswith("\n") else line)
        if strip:
            line = line.strip()
        output.append(line)

    p.wait()

    if check_result and p.returncode != 0:
        raise Return_nonzero_exception(p.returncode)

    if return_error:
        error = p.stderr.readlines()
        for line in error:
            pr_error(line[:-1] if line.endswith("\n") else line)
        if strip:
            error = [x.strip() for x in error]
        return output, error
    return output

def run(
    command: Union[str, List[str]], input: List[str] = None,
    return_all: bool = False, return_output: bool = False, return_error: bool = False,
    print_when_return: bool = False, check_result: bool = True,
    strip: bool = True, timeout: float = None, print_command: bool = None,
    wait: bool = True, shell: bool = False
) -> Union[None, List[str], Tuple[List[str], List[str]]]:
    """
    @command can be a list or string. 
             But when you set shell=True, it must be a string.
    @input should be a list containing strings line by line, if have.
    @timeout is counted as seconds.
    @print_when_return means return_output will be set to True, and timeout *must* be None.

    WARNING: don't set shell=True when you have a lot of output! It will block in read.
    """
    if return_all:
        return_output = True
        return_error = True
    if print_command is None:
        print_command = (not return_output)
    if shell:
        if is_windows:
            command = "powershell /c " + command
    else:
        if type(command) is str:
            command = command.split()
        if is_windows:
            command = ["powershell", "/c"] + command
    if print_command:
        pr_command(command)
    if input is not None:
        input = "\n".join(input) + "\n"

    if print_when_return:
        assert timeout is None
        assert not shell
        return _run_print_when_return(command, input, return_error, check_result, strip)

    import subprocess
    p = subprocess.Popen(
        command,
        stdin=(subprocess.PIPE if input else None),
        stdout=(subprocess.PIPE if return_output else None),
        stderr=(subprocess.PIPE if return_error else None),
        text=True,
        shell=shell,
    )

    if not wait:
        timeout = 0
    try:
        output, error = p.communicate(input, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        if not wait:
            return
        p.kill()
        output, error = p.communicate()
        raise Timeout_exception(e, output=output, error=error)

    def _process_output(string):
        result = string.split("\n")
        if not result[-1]:
            result = result[:-1]
        if strip:
            result = [x.strip() for x in result]
        return result

    if return_output:
        output = _process_output(output)
    if return_error:
        error = _process_output(error)

    if check_result and p.returncode != 0:
        # pr_error(f"return code: {p.returncode}")
        raise Return_nonzero_exception(p.returncode)

    if return_output and return_error:
        return output, error
    if return_output:
        return output
    if return_error:
        return error

def get(
    command: Union[str, List[str]], input: List[str] = None,
    return_error: bool = False,
    print_when_return: bool = False, check_result: bool = True,
    strip: bool = True, timeout: float = None, print_command: bool = None,
    wait: bool = True, shell: bool = False
) -> Union[List[str], Tuple[List[str], List[str]]]:
    return run(
        command, return_output=True, return_error=return_error,
        input=input, print_when_return=print_when_return, check_result=check_result,
        strip=strip, timeout=timeout, print_command=print_command,
        wait=wait, shell=shell
    )

def run_remote(
    ip: str, command: str, input: str = None,
    return_all: bool = False, return_output: bool = False, return_error: bool = False,
    check_result: bool = True, strip: bool = True, timeout: float = None,
    print_command: bool = True
) -> Union[None, List[str], Tuple[List[str], List[str]]]:
    """
    @command cannot be a list
    """
    return run(
        ["ssh", ip, command],
        input=input,
        return_all=return_all, return_output=return_output, return_error=return_error,
        check_result=check_result,
        strip=strip, timeout=timeout, print_command=print_command
    )

def get_remote(
    ip: str, command: Union[str, List[str]], input: List[str] = None,
    return_error: bool = False, check_result: bool = True,
    strip: bool = True, timeout: float = None, print_command: bool = None
) -> Union[List[str], Tuple[List[str], List[str]]]:
    return run_remote(
        ip, command, return_output=True, return_error=return_error,
        input=input, check_result=check_result,
        strip=strip, timeout=timeout, print_command=print_command
    )

def run_shell(
    command: str, ip: str = None, input: str = None,
    return_all: bool = False, return_output: bool = False, return_error: bool = False,
    check_result: bool = True, strip: bool = True, timeout: float = None,
    print_command: bool = True
) -> Union[None, List[str], Tuple[List[str], List[str]]]:
    if ip is None:
        return run(
            command, input=input,
            return_all=return_all, return_output=return_output, return_error=return_error,
            check_result=check_result, strip=strip, timeout=timeout,
            print_command=print_command, shell=True
        )
    else:
        return run_remote(
            ip, command, input=input,
            return_all=return_all, return_output=return_output, return_error=return_error,
            check_result=check_result, strip=strip, timeout=timeout,
            print_command=print_command
        )

def get_shell(
    command: str, ip: str = None, input: str = None, return_error: bool = False,
    check_result: bool = True, strip: bool = True, timeout: float = None,
    print_command: bool = True
) -> Union[List[str], Tuple[List[str], List[str]]]:
    return run_shell(
        command, ip=ip, input=input, return_output=True, return_error=return_error,
        check_result=check_result, strip=strip, timeout=timeout,
        print_command=print_command
    )

def whoami() -> str:
    import os, pwd
    return pwd.getpwuid(os.getuid())[0]

def i_am_root() -> bool:
    return whoami() == "root"

def run_sudo(command: str, password: str = "qwe123!@#", print_command: bool = True) -> None:
    if i_am_root():
        run_shell(command)
        return

    if print_command:
        pr_command("sudo -k " + command)

    expect_input = f"""
        set timeout -1
        spawn sudo -k {command}
        expect {{
            -re ": $" {{
                send "{password}\\n"
            }}
        }}
        interact
        catch wait result
        exit [lindex $result 3]
    """
    import lyt_io
    with lyt_io.temp_file(expect_input) as p:
        run(["expect", p], print_command=False)

def ssh(
    ip: str, password: str = None, command: str = None, port: int = None,
    timeout: int = 5, wait: bool = True, print_command: bool = True
) -> None:
    """
    Use this function when you need to run commands on remote machine with password.
    """
    if password is None:
        password = "Huawei12#$"
    if command is None:
        command = ""
    if port is None:
        port = 22
    expect_input = f"""
        set timeout -1
        spawn ssh -o "ConnectTimeout 5" -p {port} {ip} {command}

        expect {{
			# first connect, no public key in ~/.ssh/known_hosts
			"Are you sure you want to continue connecting*" {{
				send "yes\\n"
                expect {{
                    -re "\[P|p]assword: $" {{
                        send "{password}\\n"
                    }}

                    eof {{
                        catch wait result
                        exit [lindex $result 3]
                    }}
                }}
			}}

			# already has public key in ~/.ssh/known_hosts
			-re "\[P|p]assword: $" {{
				send "{password}\\n"
          	}}

            # successfully logged in, go through to interact
            -re "(%|#|\$|>) $" {{ }}

			## connect target machine time out
			timeout {{
				send_user "connection to {ip} timed out\\n"
				exit 13
        	}}

            ## I don't know what's it for, just keep it in case.
			eof {{ 
                catch wait result
                exit [lindex $result 3]
            }}
       	}}

        interact
        catch wait result
        exit [lindex $result 3]
    """
    import lyt_io
    pr_command("ssh")
    start_time = time()
    with lyt_io.temp_file(expect_input) as p:
        try:
            run(["expect", p], print_command=False)
        except Return_nonzero_exception as e:
            if time() - start_time > 10:
                # we have successed once to connect and exit manually,
                # no need to do anything more
                return

            pr_error(f"error code: {e.ret}")
            # success_rets = {2, 130, 255}
            # if e.ret in success_rets:
            #     return
            if not wait:
                raise e
            wait_until_remote_available(ip)
            run(["expect", p], print_command=False)

def scp(
    src: str, dest: str,
    password: str = None, port: int = None,
    timeout: int = 5, wait: bool = True,
    print_command: bool = None, return_all: bool = False
) -> None:
    if password is None:
        password = "Huawei12#$"
    if port is None:
        port = 22
    if print_command is None:
        print_command = (not return_all)
    expect_input = f"""
        set timeout -1
        spawn scp -r -o "ConnectTimeout 5" -P {port} {src} {dest}

        expect {{
			# first connect, no public key in ~/.ssh/known_hosts
			"Are you sure you want to continue connecting*" {{
				send "yes\\n"
                expect {{
                    -re "\[P|p]assword: $" {{
                        send "{password}\\n"
                    }}

                    eof {{
                        catch wait result
                        exit [lindex $result 3]
                    }}
                }}
			}}

			# already has public key in ~/.ssh/known_hosts
			-re "\[P|p]assword: $" {{
				send "{password}\\n"
          	}}

			## connect target machine time out
			timeout {{
				send_user "connection timed out\\n"
				exit 13
        	}}

			eof {{
                catch wait result
                exit [lindex $result 3]
            }}
       	}}

        interact
        catch wait result
        exit [lindex $result 3]
    """
    import lyt_io
    with lyt_io.temp_file(expect_input) as p:
        if print_command:
            pr_command("scp")
        return run(["expect", p], print_command=False, return_all=return_all)

def add_id_rsa(ip, password=None):
    import lyt_io
    pub_key = lyt_io.load_txt(get_lib_root() + "config/authorized_keys")[0]
    ssh(ip, command="mkdir -p ~/.ssh", password=password)
    added_keys = lyt_io.load_txt_remote(f"{ip}:~/.ssh/authorized_keys")
    if pub_key in added_keys:
        return
    ssh(ip, command=f'echo "{pub_key}" >> ~/.ssh/authorized_keys', password=password)

def run_multi_process(func: Callable, tasks: List, process_num: int = 6) -> List:
    from multiprocessing import Pool

    with Pool(process_num) as pool:
        result = list(tqdm(pool.imap_unordered(func, tasks), total=len(tasks)))
    return result

def wait_until_remote_available(ip: str) -> None:
    pbar = tqdm(desc="trying to connect")
    while True:
        if pbar is not None:
            pbar.update(1)
        try:
            run_remote(ip, "echo hello", return_all=True, timeout=5, print_command=False)
            break
        except (Return_nonzero_exception, Timeout_exception) as e:
            if e.output is not None and "password" in e.output:
                break
            sleep(1)
    if pbar is not None:
        pbar.close()
    print(f"{ip} is now available")

def findmnt(path, ip=None) -> str:
    return get_shell(f"findmnt {path} -o TARGET -n", ip=ip)

def kexec(ip: str = None, boot_entry: str = None) -> None:
    import lyt_io

    remote = (ip is not None)
    if boot_entry is None:
        cmdline = lyt_io.load_txt("/proc/cmdline", remote=remote)[0]
        cur_vmlinux = cmdline.split()[0].split("=")[1]
        # TODO


def kexec_and_wait(ip: str, boot_entry: str = None) -> None:
    pass

def reboot_and_wait(ip: str, boot_entry: str = None, quick: bool = True) -> None:
    if boot_entry is not None:
        pr_info(f"will reboot throgh entry: {boot_entry}")

    if quick:
        kexec_and_wait(ip, boot_entry=boot_entry)

    if boot_entry is not None:
        run_remote(ip, f"grub2-editenv - set saved_entry='{boot_entry}'")

    try:
        run_remote(ip, "reboot")
    except Return_nonzero_exception:
        pass
    sleep(5)
    wait_until_remote_available(ip)

def get_architecture() -> str:
    """
    returns "x86" or "arm"
    """
    assert not is_windows
    arch_list = {
        "x86_64": "x86",
        "aarch64": "arm"
    }
    arch_name = run("uname -m", return_output=True)[0]
    return arch_list[arch_name]

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

def set_env(env_name: str, value: any) -> None:
    if type(value) is not str:
        value = str(value)
    import os
    os.environ[env_name] = value

def get_env(env_name: str) -> str:
    import os
    return os.environ[env_name]

def get_lib_root() -> str:
    import lyt_io
    return lyt_io.get_path_parent(__file__, repeat=2)

def get_home() -> str:
    import lyt_io
    return lyt_io.format_folder(get_env("HOME"))

class work_in:
    def __init__(self, work_path: str):
        self.old_path = pwd()
        self.new_path = work_path

    def __enter__(self):
        cd(self.new_path)

    def __exit__(self, *_):
        cd(self.old_path)

def sorted_arg(seq: List, key: Callable = None) -> List:
    """
    sort a sequence and return sorted indexes
    """
    new_key = seq.__getitem__ if key is None else lambda x : key(seq[x])
    return sorted(range(len(seq)), key=new_key)

def get_ip_address(ip_prefix: str = None) -> List[str]:
    import ipaddress
    results = []

    if is_windows:
        lines = run("ipconfig", return_output=True, strip=True)
        for line in lines:
            if not line.startswith("IPv4 Address"):
                continue
            blocks = line.split(":")
            if len(blocks) <= 1:
                continue
            cur_ip = blocks[1].strip()
            if ip_prefix and not cur_ip.startswith(ip_prefix):
                continue
            try:
                ipaddress.ip_address(cur_ip)
            except ValueError:
                continue
            results.append(cur_ip)
    else:
        assert False

    return results

def parse_blocks(
    lines: List[str], start_pattern: str = None, end_pattern: str = None
) -> List[List[str]]:
    """
    WARNING: not tested!

    Promise that each block starts with start_pattern and ends with end_pattern,
    which means we only return lines in [start_pattern, end_pattern]
    Note: line with end_pattern *is* included!!!

    If end_pattern is None, no lines before start_pattern will be returned.
    The same when start_pattern is None.
    """
    if start_pattern is None and end_pattern is None:
        return [lines]
    result = []
    block = []
    in_block = start_pattern is None
    for line in lines:
        if start_pattern is not None and line.startswith(start_pattern):
            if block:
                result.append(block)
            block = [line]
            in_block = True
            continue
        if in_block:
            block.append(line)
        if end_pattern is not None and line.startswith(end_pattern):
            if block:
                result.append(block)
            block = []
            if start_pattern is not None:
                in_block = False
    
    if end_pattern is None and block:
        result.append(block)

    return result

def zip(
    src_path: str, dest_path: bool = None, zip_format: str = "zip",
    password: str = None, delete_src: bool = False, quiet:bool = False
) -> None:
    def _do_zip(src_path, dest_path):
        command = ["zip", "-r"]
        if quiet:
            command.append("-q")
        if password is not None:
            command.extend(["-P", password])
        command.extend([dest_path, src_path])
        run(command)

    def _do_tar_bz2(src_path, dest_path):
        assert password is None
        # tar -cjSf <dest> <src>
        command = ["tar", "-cjSf", dest_path, src_path]
        run(command)

    def _do_tar_gz(src_path, dest_path):
        assert password is None
        # tar -czvf <dest> <src>
        command = ["tar", "-czvf", dest_path, src_path]
        run(command)

    zip_funcs = {
        "zip": _do_zip,
        "tar.bz2": _do_tar_bz2,
        "tar.gz": _do_tar_gz
    }
    zip_func = zip_funcs[zip_format]

    import lyt_io
    src_dir = lyt_io.get_path_parent(src_path)
    src_name = lyt_io.get_path_name(src_path)
    if dest_path is None:
        # this means src and dest will be under same parent, so only names needed
        if lyt_io.is_dir(src_path):
            dest_path = src_name + "." + zip_format
        else:
            dest_path = lyt_io.get_path_stem(src_path) + "." + zip_format

    with work_in(src_dir):
        zip_func(src_name, dest_path)

    if delete_src:
        rm(src_path)

def unzip(
    src_path: str, dest_path: str = None, passwords: str = None,
    delete_src: bool = False, quiet: bool = False, unrar_command: str = "unrar"
) -> None:
    """
    need command "unrar" command if you want to decompress .rar files
    You can specify how to run unrar in parameter "unrar_command",
    eg. unrar_command="./path/to/unrar"
    """
    def _do_unzip(src_path, dest_path, password):
        command = ["unzip"]
        if quiet:
            command.append("-qq")
        if password is not None:
            command.extend(["-P", password])
        command.extend([src_path, "-d", dest_path])
        run(command, print_command=not quiet)

    def _do_untar(src_path, dest_path, password):
        assert False

    def _do_unrar(src_path, dest_path, password):
        command = [unrar_command, "e", src_path]
        if password is not None:
            command.append(f"-p{password}")
        command.append(f"-op{dest_path}")
        if quiet:
            command.append("-inul")
        run(command, print_command=not quiet)

    unzip_funcs = {
        ".zip": _do_unzip,
        ".tar.gz": _do_untar,
        ".tar.xz": _do_untar,
        ".rar": _do_unrar,
    }
    unzip_func = None
    # if not found, unzip_func will keep to be None
    for suffix, f in unzip_funcs.items():
        if src_path.endswith(suffix):
            unzip_func = f
            break

    if dest_path is None:
        import lyt_io
        dest_path = lyt_io.get_path_parent(src_path)
    if type(passwords) is not list:
        passwords = [passwords]

    success = False
    for p in passwords:
        try:
            unzip_func(src_path, dest_path, p)
        except Return_nonzero_exception:
            continue
        success = True
        break

    if not success:
        raise Return_nonzero_exception(0)

    if delete_src:
        rm(src_path)

def argv() -> List[str]:
    import sys
    return sys.argv

def get_caller_name(depth: int = 1) -> str:
    import inspect
    return inspect.stack()[depth + 1].function

def get_function_name() -> str:
    return get_caller_name()

def get_file_auther(path) -> str:
    data = get(f"git blame {path} --line-porcelain | grep '^author '", shell=True)
    counter = {}
    for line in data:
        name = line.split(" ", 1)[1]
        counter[name] = counter.setdefault(name, 0) + 1
    return max(counter, key=counter.get)

def get_file_euler_auther(path) -> str:
    """
    this function find who signs off when the file is added
    """
    data = get(["git", "log", "--diff-filter=A", "--", path])

    def try_find_name(name):
        """
        try to find standard name from email
        """
        blocks = name.split()
        found = False
        for b in blocks:
            if "@" not in b:
                continue
            found = True
            break
        if not found:
            return name
        
        try:
            start = [x.isalpha() for x in b].index(True)
            b = b[start:]
            end = [x.isalpha() for x in b].index(False)
            b = b[:end]
        except IndexError:
            return name
        return b

    for line in data:
        line = line.strip()
        if line.startswith("Signed-off-by: "):
            return try_find_name(line[15:])
    return None

def get_element(data: Mapping, *args: any) -> any:
    try:
        for index in args:
            data = data[index]
        return data
    except KeyError:
        return None

# alias
b2h = bytes_to_human
