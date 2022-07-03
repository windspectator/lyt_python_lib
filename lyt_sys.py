from typing import Dict, Union, List, Set
import lyt_utils as l

# deprecated!
class Mem_ranges_old:
    ranges = None
    def __init__(self, ranges=[]):
        self.ranges = ranges

    def add(self, new_range):
        self.ranges.append(new_range)

    def intersect(self, b):
        result = []
        i = j = 0
        while i < len(self.ranges) and j < len(b.ranges):
            l = max(self.ranges[i][0], b.ranges[j][0])
            r = min(self.ranges[i][1], b.ranges[j][1])
            if l < r:
                result.append([l, r])
            
            if self.ranges[i][1] < b.ranges[j][1]:
                i += 1
            else:
                j += 1

        return Mem_ranges_old(result)

    def print(self, sorted_by_size=False):
        if sorted_by_size:
            result = sorted(self.ranges, key=lambda x : x[1] - x[0], reverse=True)
        else:
            result = sorted(self.ranges, key=lambda x : x[0])
        sum_mem = 0
        for r in result:
            print(f"{hex(r[0])}-{hex(r[1])}: {l.bytes_to_human(r[1] - r[0])}")
            sum_mem += r[1] - r[0]
        print(f"in total: {l.bytes_to_human(sum_mem)}, {sum_mem} B")

class Mem_ranges:
    intervals_module = None

    # self.ranges: intervals.Interval

    def __init__(self, ranges=None):
        if Mem_ranges.intervals_module is None:
            Mem_ranges.intervals_module = l.try_import("intervals", "python-intervals")
        intervals = Mem_ranges.intervals_module
        
        if type(ranges) is intervals.Interval:
            self.ranges = ranges
            return

        self.ranges = intervals.open(0, 0)
        if ranges is None:
            return
        
        for start, end in ranges:
            self.ranges |= intervals.closedopen(start, end)

    def __sub__(self, b):
        return Mem_ranges(self.ranges - b.ranges)

    def print(self, sorted_by_size=False):
        print(self.ranges)

# [0]     name            
# [1~6]   <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : 
# [7~11]  tunables <limit> <batchcount> <sharedfactor> : 
# [12~15] slabdata <active_slabs> <num_slabs> <sharedavail>
def get_slabinfo(path=None):
    """
    returns a dictinary: {
        slab_name1: {
            active_objs: ...,
            num_objs: ...,
            objsize: ...,
            objperslab: ...,
            pagesperslab: ...,
        },
        slab_name2: ...,
        ...
    }
    """
    import lyt_io
    if path is None:
        path = "/proc/slabinfo"

    data = lyt_io.load_txt(path)[2:]
    slabinfo = {}
    for d in data:
        blocks = d.split()
        slabinfo[blocks[0]] = {
            "active_objs": int(blocks[1]),
            "num_objs": int(blocks[2]),
            "objsize": int(blocks[3]),
            "objperslab": int(blocks[4]),
            "pagesperslab": int(blocks[5]),
        }

    return slabinfo

def get_pname(pid: int) -> str:
    import lyt_io
    try:
        cmdline = lyt_io.load_txt(f"/proc/{pid}/cmdline")
    except FileNotFoundError:
        return None
    if not cmdline:
        return None
    return cmdline[0].replace('\x00', ' ').strip()

def get_pid(pname: str = None) -> int:
    if pname is None:
        import os
        result = os.getpid()
    else:
        result = l.run(f"pidof {pname}", return_output=True)[0]

    return result

def get_all_pids() -> List[int]:
    pids = l.run("ps -eo pid", return_output=True)[1:]
    return [int(x.strip()) for x in pids]

# address perms offset dev inode pathname
def get_smaps(pid: int) -> List[Dict[str, Union[int, str, Set[str]]]]:
    """
    each segment contains keys below:

    address:    virtual address range
    perms:      permission of this vma
    offset:     the offset into the file/whatever
    dev:        the device (major:minor)
    inode:      inode on that device, 0 means no inode
    pathname:   the file that is backing the mapping
    pseudo-path: stack/heap/vdso/... else None
    ...:        and other original keys in smaps
    """
    import lyt_io
    try:
        data = lyt_io.load_txt(f"/proc/{pid}/smaps")
    except FileNotFoundError:
        return None
    result = l.parse_blocks(data, end_pattern="VmFlags:")

    for i, d in enumerate(result):
        blocks = d[0].split()
        seg = {
            "address": blocks[0],
            "perms": blocks[1],
            "offset": blocks[2],
            "dev": blocks[3],
            "inode": blocks[4],
            "pathname": None,
            "pseudo-path": None,
        }
        if len(blocks) >= 6:
            pathname = " ".join(blocks[5:])
            if pathname.startswith("[") and pathname.endswith("]"):
                seg["pseudo-path"] = pathname[1:-1]
            else:
                seg["pathname"] = pathname

        for line in d[1:-1]:
            name, size = line.split(":")
            size = int(size.strip().split()[0])
            seg[name] = size

        # VmFlags is special
        name, value = d[-1].split(":")
        value = value.lstrip()
        seg[name] = set(value.split())

        result[i] = seg

    return result

def get_file_size(path):
    """
    returned size is in KB
    """
    result = l.run(["du", "-s", path], return_output=True)[0]
    return int(result.split()[0])

def _get_all_params_in_dir(path: str) -> Dict[str, str]:
    """
    Warning: only read first line in file!
    """
    import lyt_io

    result = {}
    keys = lyt_io.get_path_children(path, only_file=True, only_name=True)
    for k in keys:
        result[k] = lyt_io.load_txt(path + k)[0]

    return result

def get_zswap() -> Dict[str, int]:
    result = _get_all_params_in_dir("/sys/kernel/debug/zswap/")

    for k, v in result.items():
        result[k] = int(v)

    return result

def _get_grub_cfg(path: str, remote: bool = False):
    """
    returns a dictinary: {
        entry_name1: {
            id: ...,
            vmlinux: ...,
            append: ...,
            initrd: ...,
        },
        entry_name2: ...,
        ...
    }
    """
    import lyt_io

    lines = lyt_io.load_txt(path, remote=remote)
    # print(len(lines))
    # TODO

grub_paths = [
    "/boot/efi/EFI/EulerOS/grub.cfg",
    "/boot/grub2/grub.cfg",
    "/boot/efi/EFI/openEuler/grub.cfg",
]
def get_grub_cfg(ip: str = None):
    """
    if remote is set, you should pass remote ip in parameter 'path'
    """
    import lyt_io

    remote = (ip is not None)
    grub_path = None
    for p in grub_paths:
        if remote:
            p = f"{ip}:{p}"
        if not lyt_io.is_path_exist(p, remote=remote):
            continue
        grub_path = p
        break

    return _get_grub_cfg(grub_path, remote=remote)

def get_grub_cfg_remote(ip):
    """

    """

# alias
pids = get_all_pids
smaps = get_smaps
pid = get_pid
pname = get_pname

