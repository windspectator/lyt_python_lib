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
    string: any, color: str = "violet", prefix: str = "", suffix: str = ""
) -> None:
    if type(string) is list:
        string = " ".join(string)
    if type(string) is not str:
        string = str(string)

    print(prefix + dye(string, color=color) + suffix)

def pr_error(string: any, prefix: str = "", suffix: str = "") -> None:
    print_in_color(string, color="red", prefix=prefix, suffix=suffix)

def pr_warn(string: any, prefix: str = "", suffix: str = "") -> None:
    print_in_color(string, color="orange", prefix=prefix, suffix=suffix)

def pr_notice(string: any, prefix: str = "", suffix: str = "") -> None:
    print_in_color(string, color="violet", prefix=prefix, suffix=suffix)

def pr_info(string: any, prefix: str = "", suffix: str = "") -> None:
    print_in_color(string, color="green", prefix=prefix, suffix=suffix)

def pr_debug(string: any, prefix: str = "", suffix: str = "") -> None:
    print_in_color(string, color="black", prefix=prefix, suffix=suffix)

def pr_command(command: str) -> None:
    pr_notice(command, prefix="-----> ", suffix=" <-----")
