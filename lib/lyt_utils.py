from typing import Union, List, Callable, Tuple, Iterable, Mapping

from base import is_windows, platform, try_import, whoami, i_am_root, set_low_priority, \
    get_terminal_size, get_terminal_size_hw, tic, toc, is_iterable, work_in, \
    run_multi_process, time
from lyt_print import dye, print_in_color, \
    pr_error, pr_warn, pr_notice, pr_info, pr_debug, pr_command
from exception import Timeout_exception, Return_nonzero_exception
from run import run, get, run_remote, get_remote, run_shell, get_shell, run_sudo
from linux_commands import cd, cp, rm, mkdir, pwd, mv, echo

def _bytes_to_human(byte_num: int) -> str:
    if byte_num < 1024:
        return f"{byte_num} B"
    unit_list = ["KB", "MB", "GB", "TB"]
    unit_num = byte_num
    for unit in unit_list:
        unit_num /= 1024
        if unit_num < 1024:
            return "{:.2f} {}".format(unit_num, unit)
    return "{:.2f} {}".format(unit_num, unit_list[-1])

def bytes_to_human(byte_num: int) -> str:
    if byte_num < 0:
        return "-" + _bytes_to_human(-byte_num)
    return _bytes_to_human(byte_num)

def kb_to_human(kb_num: int) -> str:
    return bytes_to_human(1024 * kb_num)

def pages_to_human(page_num: int) -> str:
    return bytes_to_human(4096 * page_num)

def sleep(sec: float) -> None:
    """
    @sec: sleep time in seconds, can be a float number
    """
    import time
    time.sleep(sec)

def enter_pexpect(command: str, timeout: int = 30, env: any = None):
    import pexpect, signal
    child = pexpect.spawn(command, timeout=timeout, env=env)
    child.setwinsize(*get_terminal_size_hw())
    signal.signal(signal.SIGWINCH, lambda *_ : child.setwinsize(*get_terminal_size_hw()))

    return child

def exit_pexpect(child: any):
    import signal
    child.close()
    signal.signal(signal.SIGWINCH, signal.SIG_DFL)

def su(password: str = None) -> None:
    if i_am_root():
        return

    if password is None:
        password = "Huawei12#$"

    expect_list = [": $"]
    p = enter_pexpect("su -p", env=get_env())
    p.expect(expect_list)
    p.sendline(password)
    print((p.before + p.after).decode(), end="")
    p.interact()
    exit_pexpect(p)

def is_remote_available(
    ip: str, port: int = None, timeout: int = 5
) -> None:
    if port is None:
        port = 22

    import pexpect
    expect_list = [
        "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!",
        "Are you sure you want to continue connecting*",
        "[P|p]assword: ",
        "(%|#|\$|>) $",
        pexpect.EOF,
        pexpect.TIMEOUT,
    ]
    p = enter_pexpect(f"ssh {ip} -p {port}", timeout=timeout)
    i = p.expect(expect_list, timeout=timeout)
    exit_pexpect(p)
    if i >= 4:
        return False
    return True

def wait_until_remote_available(ip: str, port: int = None) -> None:
    from lyt_tqdm import tqdm
    pbar = tqdm(desc="trying to connect")
    while not is_remote_available(ip, port=port):
        pbar.update(1)
        sleep(1)
    pbar.close()
    pr_info(f"{ip} is now available")

def ssh(
    ip: str, password: str = None, command: str = None, port: int = None,
    timeout: int = 5, wait: bool = True, print_command: bool = True,
    interact: bool = False
) -> None:
    """
    Use this function when you need to run commands on remote machine with password.
    """
    if password is None:
        password = "Huawei12#$"
    if port is None:
        port = 22

    if print_command:
        pr_command("ssh " + ip)

    import pexpect
    expect_list = [
        "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!",
        "Are you sure you want to continue connecting*",
        "[P|p]assword: ",
        "(%|#|\$|>) $",
        pexpect.EOF,
        pexpect.TIMEOUT,
    ]
    def do_ssh():
        p = enter_pexpect(f"ssh {ip} -p {port}", timeout=timeout)

        def do_expect(start_index):
            i = p.expect(expect_list[start_index:], timeout=timeout) + start_index
            if i == 4:
                exit_pexpect(p)
                raise Return_nonzero_exception(0)
            if i == 5:
                exit_pexpect(p)
                raise Timeout_exception()
            print((p.before + p.after).decode(), end="")

            return i
        
        def remove_known_host(ip_addr, port):
            if port == 22:
                run(f'ssh-keygen -f ~/.ssh/known_hosts -R "{ip_addr}"', shell=True)
            else:
                run(f'ssh-keygen -f ~/.ssh/known_hosts -R "[{ip_addr}]:{port}"', shell=True)

        i = do_expect(0)
        if i == 0:
            exit_pexpect(p)
            ip_addr = ip.split("@")[1]

            remove_known_host(ip_addr, port)
            do_ssh()
            return

        if i == 1:
            p.sendline("yes")
            i = do_expect(2)

        if i == 2:
            p.sendline(password)
            do_expect(3)

        if command is None:
            p.interact()
            exit_pexpect(p)
            return

        p.sendline(command)
        if interact:
            p.interact()
            exit_pexpect(p)
            return

        do_expect(3)
        p.sendline("exit")
        try:
            do_expect(3)
        except Return_nonzero_exception:
            print((p.before).decode(), end="")

        exit_pexpect(p)

    start_time = time()
    try:
        do_ssh()
    except (Return_nonzero_exception, Timeout_exception) as e:
        if time() - start_time > timeout + 1:
            # we have successed once to connect and exit manually,
            # no need to do anything more
            return

        # pr_error(f"error code: {e.ret}")
        # success_rets = {2, 130, 255}
        # if e.ret in success_rets:
        #     return
        if not wait:
            raise e
        wait_until_remote_available(ip, port=port)
        do_ssh()

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

def add_id_rsa(ip, password=None, port=None, add_private_key=False):
    def _do_add_id_rsa(ip, port):
        scp(get_home() + ".ssh/id_rsa", ip + ":~/.ssh/", port=port)

    # check if we already can connect without password
    try:
        ssh(ip, command="echo hello", port=port, wait=False, password="", timeout=3)
        if add_private_key:
            _do_add_id_rsa(ip, port)
        return
    except (Return_nonzero_exception, Timeout_exception):
        print()

    import lyt_io
    pub_key = lyt_io.load_txt(get_lib_root() + "config/authorized_keys")[0]
    ssh(ip, command="mkdir -p ~/.ssh && chmod 700 ~/.ssh", password=password, port=port)
    ssh(
        ip,
        command=f'echo "{pub_key}" >> ~/.ssh/authorized_keys',
        password=password, port=port
    )
    ssh(ip, command="chmod 600 ~/.ssh/authorized_keys", password=password, port=port)
    ssh(
        ip, password=password, port=port,
        command="sed -i 's/export TMOUT=.*$/export TMOUT=0/g' /etc/profile"
    )
    if add_private_key:
        _do_add_id_rsa(ip, port)

def findmnt(path, ip=None) -> str:
    return get_shell(f"findmnt {path} -o TARGET -n", ip=ip)

def kexec(ip: str = None, boot_entry: str = None) -> None:
    import lyt_io

    remote = (ip is not None)
    if boot_entry is None:
        cmdline = lyt_io.load_txt("/proc/cmdline", remote=remote)[0]
        cur_vmlinux = cmdline.split()[0].split("=")[1]
        # TODO


def kexec_and_wait(ip: str, boot_entry: str = None, port: int = None, arch: str = None) -> None:
    import lyt_sys

    entry = None
    if boot_entry is None:
        uname = run_remote(ip, "uname -r", return_output=True)[0]
        entries = lyt_sys.get_grub_cfg(ip=ip, arch=arch)
        for e in entries:
            if uname in e:
                entry = entries[e]
    else:
        entry = lyt_sys.get_grub_cfg(ip=ip, arch=arch)[boot_entry]
    run_remote(
        ip,
        "kexec -l" + \
            " /boot" + entry["vmlinux"] + \
            ' --append="' + entry["append"].replace('"', '\\\"') + '"' + \
            " --initrd=/boot" + entry["initrd"],
        port=port,
    )
    try:
        run_remote(ip, "kexec -e", check_result=False, timeout=3)
    except Timeout_exception:
        pass

    # sleep(5)
    wait_until_remote_available(ip, port=port)

def reboot_and_wait(
    ip: str, boot_entry: str = None, quick: bool = False, port: int = None, arch: str = None
) -> None:
    if boot_entry is not None:
        pr_info(f"will reboot throgh entry: {boot_entry}")

    if boot_entry is not None:
        run_remote(ip, f"grub2-editenv - set saved_entry='{boot_entry}'", port=port)

    if quick:
        run_remote(ip, "sync", port=port)
        return kexec_and_wait(ip, boot_entry=boot_entry, port=port, arch=arch)

    run_remote(ip, "reboot", port=port, check_result=False)
    sleep(5)
    wait_until_remote_available(ip, port=port)

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

def set_env(env_name: str, value: any) -> None:
    if type(value) is not str:
        value = str(value)
    import os
    os.environ[env_name] = value

def get_env(env_name: str = None) -> str:
    import os
    if env_name is None:
        return os.environ
    return os.environ[env_name]

def get_lib_root() -> str:
    import lyt_io
    return lyt_io.get_path_parent(__file__, repeat=2)

def get_config_root() -> str:
    return get_lib_root() + "config/"

def get_home() -> str:
    import lyt_io
    return lyt_io.format_folder(get_env("HOME"))

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

def make_lib_patch():
    import lyt_io
    d = lyt_io.get_temp_dir_path()
    cp(get_lib_root() + "lib/", d)
    dest = pwd()
    with work_in(d):
        lyt_io.save_txt(".gitignore", ["__pycache__/", ".gitignore"])
        run("git init .")
        run("git add -A")
        run("git commit -m 't'")
        patch_name = get("git format-patch -1")[0]
    cp(d + patch_name, dest)

def apply_lib_patch(path : str = None):
    import lyt_io
    if path is None:
        path = pwd() + "0001-t.patch"

    dest = pwd()
    d = lyt_io.get_temp_dir_path()
    d = d + "lyt_python_lib/"
    mkdir(d)
    with work_in(d):
        run("git init .")
        run(f"git apply {path}")
    cp(d, dest)

# alias
b2h = bytes_to_human
kb2h = kb_to_human
p2h = pages_to_human
