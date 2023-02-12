from typing import Union, List, Callable, Tuple, Iterable, Mapping
from exception import *
from base import *
from lyt_print import *

is_windows = False

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
    @input can be a list or string.
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
        if not wait and not shell:
            command += "&"
        pr_command(command)
    if type(input) is list:
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
    print_command: bool = True, port: int = None
) -> Union[None, List[str], Tuple[List[str], List[str]]]:
    """
    @command cannot be a list
    """
    if port is None:
        port = 22
    return run(
        ["ssh", ip, "-p", str(port), command],
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
