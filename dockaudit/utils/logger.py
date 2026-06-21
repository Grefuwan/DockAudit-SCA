import logging
import sys


def setup_logging(debug: bool = False, log_file: str = None) -> None:
    fmt = "%(asctime)s_-_%(filename)s_-_%(funcName)s_-_%(levelname)s: %(message)s"
    datefmt = "%Y%m%d-%H%M%S"
    console_level = logging.DEBUG if debug else logging.INFO

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(console_level)
    console.setFormatter(logging.Formatter(fmt, datefmt=datefmt))
    root.addHandler(console)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(fmt, datefmt=datefmt))
        root.addHandler(file_handler)
