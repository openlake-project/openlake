import os
import sys
from importlib.resources import files


def main():
    exe = str(files("openlake_client") / "openlaked")
    args = sys.argv[1:]
    if "--config" not in args:
        args = ["--config", str(files("openlake_client") / "configs" / "default.toml"), *args]
    os.chmod(exe, 0o755)
    os.execv(exe, ["openlaked", *args])


if __name__ == "__main__":
    main()
