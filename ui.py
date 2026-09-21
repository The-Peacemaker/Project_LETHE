"""Terminal presentation layer: colors, banners, teleprompter hints."""

import os as _os
import shutil as _shutil


def enable_color():
    """Enable ANSI colors on Windows consoles; no-op elsewhere."""
    if _os.name != "nt":
        return
    try:
        import ctypes as _ct
        _k = _ct.windll.kernel32
        _h = _k.GetStdHandle(-11)
        _m = _ct.c_ulong(0)
        _k.GetConsoleMode(_h, _ct.byref(_m))
        _k.SetConsoleMode(_h, _m.value | 0x0004)
    except Exception:
        pass


class C:
    reset = "\x1b[0m"
    bold = "\x1b[1m"
    dim = "\x1b[2m"
    cyan = "\x1b[96m"
    green = "\x1b[92m"
    yellow = "\x1b[93m"
    red = "\x1b[91m"
    magenta = "\x1b[95m"
    white = "\x1b[97m"


def width():
    try:
        return min(_shutil.get_terminal_size().columns, 100)
    except Exception:
        return 88


def rule(char="="):
    print(C.dim + char * width() + C.reset)


def title(text):
    rule("=")
    print(C.bold + C.cyan + text.center(width()) + C.reset)
    rule("=")


def scene(num, text):
    print()
    print(C.bold + C.yellow + f"SCENE {num}  |  {text}" + C.reset)
    rule("-")


def say(text):
    print(C.dim + f"  SAY: {text}" + C.reset)


def ok(label, value="OK"):
    print(f"  {C.green}OK{C.reset}  {label:<46} {C.green}{value}{C.reset}")


def info(label, value):
    print(f"       {label:<46} {value}")


def bad(label, value):
    print(f"  {C.red}XX{C.reset}  {label:<46} {C.red}{value}{C.reset}")


def arrow(text):
    print(f"  {C.magenta}>>>{C.reset} {text}")


def pause(auto):
    if auto:
        print()
        return
    try:
        input(C.dim + "  [ ENTER for next scene ]" + C.reset)
    except EOFError:
        pass


def clear():
    try:
        _os.system("cls" if _os.name == "nt" else "clear")
    except Exception:
        print("\n" * 3)