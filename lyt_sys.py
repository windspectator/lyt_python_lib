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

def get_pid(pname=None):
    if pname is None:
        import os
        result = os.getpid()
    else:
        import lyt_utils
        result = lyt_utils.run(f"pidof {pname}", return_output=True)[0]

    return result

def get_smaps(pid):
    pass