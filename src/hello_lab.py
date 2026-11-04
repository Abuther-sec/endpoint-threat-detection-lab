"""Smoke test: confirms the Python environment for the project works."""
import platform
import sys
from datetime import datetime


def main():
    print("Endpoint Threat Detection Lab - environment check")
    print("Python version :", platform.python_version())
    print("Platform       :", platform.system(), platform.release())
    print("Interpreter    :", sys.executable)
    print("Local time     :", datetime.now().isoformat(timespec="seconds"))


if __name__ == "__main__":
    main()
