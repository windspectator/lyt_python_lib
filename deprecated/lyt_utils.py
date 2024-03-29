import sys
assert sys.version_info[0] >= 3 and sys.version_info[1] >= 7, "need to be run under python 3.7+"
is_windows = (sys.platform == "win32")     # win32 or others

class Timeout_exception(Exception):
    pass

class Return_nonzero_exception(Exception):
    pass

def print_in_color(string, color="violet", prefix="", subfix=""):
    if type(string) is list:
        string = " ".join(string)
    color_list = {
        "violet": "8700A8",
        "red": "A31515",
        "orange": "D75F00",
        "green": "22855C",
        "black": "000000",
    }
    color_code = color_list[color]
    r, g, b = [int(color_code[i:i + 2], 16) for i in range(0, 6, 2)]
    COLOR = f"\033[38;2;{r};{g};{b}m"
    ORIGIN = '\033[0m'

    print(prefix + COLOR + string + ORIGIN + subfix)

def pr_error(str, prefix="", subfix=""):
    print_in_color(str, color="red", prefix=prefix, subfix=subfix)

def pr_warn(str, prefix="", subfix=""):
    print_in_color(str, color="orange", prefix=prefix, subfix=subfix)

def pr_notice(str, prefix="", subfix=""):
    print_in_color(str, color="violet", prefix=prefix, subfix=subfix)

def pr_info(str, prefix="", subfix=""):
    print_in_color(str, color="green", prefix=prefix, subfix=subfix)

def pr_debug(str, prefix="", subfix=""):
    print_in_color(str, color="black", prefix=prefix, subfix=subfix)

# same as tic/toc in matlab
timer = 0
def tic():
    import time
    # reset timer
    global timer
    timer = time.time()

def toc(print_time=True, reset_timer=True, return_str=True):
    import time
    global timer

    cur_time = time.time()
    elasped_time = cur_time - timer

    def get_str(seconds):
        m, s = divmod(seconds, 60)
        s = "{:.2f}".format(s)
        m = int(m)
        if m == 0:
            return f"elasped time is {s} seconds"
        h, m = divmod(m, 60)
        if h == 0:
            return f"elasped time is {m}:{s}"
        return f"elasped time is {h}:{m}:{s}"

    if reset_timer:
        timer = cur_time

    elasped_str = get_str(elasped_time)
    if print_time:
        print(elasped_str)

    return elasped_str if return_str else elasped_time

def sleep(sec):
    """
    @sec: sleep time in seconds, can be a float number
    """
    import time
    time.sleep(sec)

def set_low_priority():
    import os
    if sys.platform == "win32":
        import psutil
        p = psutil.Process(os.getpid())
        p.nice(psutil.IDLE_PRIORITY_CLASS)  # BELOW_NORMAL_PRIORITY_CLASS
    else:
        os.nice(20)

def run_command(command, input=None, 
                return_all=False, return_output=False, return_error=False,
                print_when_return=False, check_result=True,
                strip=True, timeout=None, print_command=None, wait=True, shell=False,
                show_progress=False):
    """
    @command can be a list or string. 
             But when you set shell=True, it must be a string.
    @input should be a list containing strings line by line, if have.
    @timeout is counted as seconds.

    WARNING: don't set shell=True when you have a lot of output! It will block in read.
    """
    if return_all:
        return_output = True
        return_error = True
    if print_command is None:
        if return_output:
            print_command = False
        else:
            print_command = True
    if shell:
        if is_windows:
            command = "powershell /c " + command
    else:
        if type(command) is str:
            command = command.split()
        if is_windows:
            command = ["powershell", "/c"] + command
    if print_command:
        pr_notice(command, prefix="-----> ", subfix=" <-----")
    if input is not None:
        input = "\n".join(input) + "\n"

    import subprocess
    p = subprocess.Popen(
        command,
        stdin=(subprocess.PIPE if input else None),
        stdout=(subprocess.PIPE if return_output else None),
        stderr=(subprocess.PIPE if return_error else None),
        text=True,
        shell=shell,
    )

    if input:
        p.stdin.write(input)
        p.stdin.flush()
    
    if not wait:
        return

    output = []
    error = []
    if return_output and print_when_return:
        for line in p.stdout:
            print(line[:-1] if line.endswith("\n") else line)
            if strip:
                line = line.strip()
            output.append(line)

    try:
        p.wait(timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise Timeout_exception(e)

    if return_output and not print_when_return:
        output = p.stdout.readlines()
        if strip:
            output = [x.strip() for x in output]
    if return_error:
        error = p.stderr.readlines()
        if strip:
            error = [x.strip() for x in error]

    if check_result and p.returncode != 0:
        raise Return_nonzero_exception()

    if return_output and return_error:
        return output, error
    if return_output:
        return output
    if return_error:
        return error

def run_remote(ip, command, input=None, return_output=False, return_error=False,
               strip=True, timeout=None, print_command=None):
    """
    @command cannot be a list
    """
    if print_command is None:
        print_command = True
    return run_command(
        f"ssh {ip} {command}", 
        input=input, return_output=return_output, return_error=return_error,
        strip=strip, timeout=timeout, print_command=print_command
    )

def run_multi_process(process_num):
    from multiprocessing import Pool
    from tqdm import tqdm

    # TODO
    assert False
    with Pool(process_num) as pool:
        r = list(tqdm(pool.imap_unordered(do, files), total=len(files)))
    return r

def wait_utill_remote_available(ip):
    from tqdm import tqdm
    pbar = tqdm(desc="trying to connect")
    while True:
        pbar.update(1)
        try:
            run_remote(ip, "echo hello", return_output=True, return_error=True, timeout=5)
            break
        except Return_nonzero_exception:
            sleep(1)
    pbar.close()
    print(f"{ip} is now available")

def reboot_and_wait(ip, boot_entry=None):
    if boot_entry is not None:
        print_in_color(f"will reboot throgh entry: {boot_entry}")
    raw_line_start = "saved_entry="
    def change_default_boot_line(line):
        if line.startswith(raw_line_start):
            return raw_line_start + boot_entry
        else:
            return line

    import lyt_io
    if boot_entry:
        lyt_io.edit_file_by_line_remote(ip, "/boot/grub2/grubenv", change_default_boot_line)
    try:
        run_remote(ip, "reboot")
    except Return_nonzero_exception:
        pass
    sleep(5)
    wait_utill_remote_available(ip)

def get_architecture():
    assert not is_windows
    arch_list = {
        "x86_64": "x86",
        "aarch64": "arm"
    }
    arch_name = run_command("uname -m", return_output=True)[0]
    return arch_list[arch_name]

def cd(path):
    import os
    os.chdir(path)

def sorted_arg(seq, key=None):
    """
    sort a sequence and return sorted indexes
    """
    new_key = seq.__getitem__ if key is None else lambda x : key(seq[x])
    return sorted(range(len(seq)), key=new_key)

def get_ip_address(ip_prefix=None):
    import ipaddress
    results = []

    if is_windows:
        lines = run_command("ipconfig", return_output=True, strip=True)
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



