import os
import sys
from importlib.resources import files


def main():
    exe = str(files("openlake_client") / "openlaked")
    os.chmod(exe, 0o755)
    os.execv(exe, ["openlaked", *sys.argv[1:]])


if __name__ == "__main__":
    main()
