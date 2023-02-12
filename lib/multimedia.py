# from base import *
from linux_commands import *

headers = {
    "accept": "*/*",
    "accept-encoding": "gzip, deflate, br",
    "accept-language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,en-CN;q=0.6,zh-TW;q=0.5",
    "origin": "https://google.com",
    "referer": "https://google.com/",
    "sec-ch-ua": '"Google Chrome";v="105", "Not)A;Brand";v="8", "Chromium";v="105"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "cross-site",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36",
}

def wget_raw(
    url: str, dest: str = None, headers: Mapping = None, proxies: Mapping = None
):
    if dest is None:
        dest = url.split("/")[-1]

    import requests
    try:
        r = requests.get(
            url,
            headers=headers,
            proxies=proxies
        )
        if r.status_code != 200:
            return False
        with open(dest, 'wb') as f:
            f.write(r.content)
    except:
        return False
    return True

def get_m3u8(
    url: str, key: str = None, dest: str = None, name: str = None,
    headers: Mapping = None, process_num: int = 30
):
    if name is None:
        name = url.split("/")[-1]
    if dest is None:
        dest = pwd()

    def parse_m3u8():
        lines = io.load_txt("index.m3u8")
        lines = filter(lambda x : x.endswith(".ts"), lines)
        return lines

    prefix = url[:url.rfind("/") + 1]

    import lyt_io as io
    workspace = io.get_temp_dir_path()
    with work_in(workspace):
        wget_raw(url, "index.m3u8")
        slices = parse_m3u8()
        params = [(prefix + x, x) for x in slices]
        results = run_multi_process(wget_raw, params, process_num=process_num)
