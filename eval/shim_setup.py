import os
import stat


def shim_dir() -> str:
    d = os.path.abspath(os.path.join(os.path.dirname(__file__), "shim"))
    wrapper = os.path.join(d, "claude")
    if os.path.isfile(wrapper):
        st = os.stat(wrapper)
        if not st.st_mode & stat.S_IXUSR:
            os.chmod(wrapper, st.st_mode | 0o755)
    return d
