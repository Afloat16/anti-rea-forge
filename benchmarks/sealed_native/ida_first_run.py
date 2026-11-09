"""One-off startup interaction for the digest-pinned freeware research run."""
import os
import subprocess


def windows_for_pid(pid):
    """Inspect this IDA process only. Return visible forms and short control labels."""
    import ctypes
    from ctypes import wintypes

    user = ctypes.WinDLL("user32", use_last_error=True)
    callback = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user.IsWindowVisible.argtypes = [wintypes.HWND]
    user.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user.EnumWindows.argtypes = [callback, wintypes.LPARAM]
    user.EnumChildWindows.argtypes = [wintypes.HWND, callback, wintypes.LPARAM]
    forms = []

    def describe(hwnd):
        name = ctypes.create_unicode_buffer(120)
        cls = ctypes.create_unicode_buffer(80)
        user.GetWindowTextW(hwnd, name, len(name))
        user.GetClassNameW(hwnd, cls, len(cls))
        return {"class": cls.value, "caption": " ".join(name.value.split())}

    @callback
    def top(hwnd, _):
        owner = wintypes.DWORD()
        user.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value != pid or not user.IsWindowVisible(hwnd):
            return True
        info = describe(hwnd)
        info["controls"] = []
        agree = []
        okay = []

        @callback
        def child(handle, _):
            if user.IsWindowVisible(handle) and len(info["controls"]) < 32:
                control = describe(handle)
                info["controls"].append(control)
                if control == {"class": "TButton", "caption": "I Agree"}:
                    agree.append(handle)
                if control == {"class": "TButton", "caption": "OK"}:
                    okay.append(handle)
            return True

        user.EnumChildWindows(hwnd, child, 0)
        labels = {(c["class"], c["caption"]) for c in info["controls"]}
        if (os.environ.get("RG_IDA_CONFIRM_FREEWARE") == "1"
                and info["class"] == "TLicenseForm" and info["caption"] == "IDA Pro License"
                and len(agree) == 1 and ("TButton", "I Disagree") in labels):
            # Only the known vendor license form of the digest-pinned, single-user freeware.
            user.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
            if not user.PostMessageW(agree[0], 0x00F5, 0, 0):  # BM_CLICK
                raise ctypes.WinError(ctypes.get_last_error())
            info["action"] = "I Agree clicked on IDA Pro License"
        if (info["class"] == "TAboutBox" and info["caption"] == "About" and len(okay) == 1
                and ("TCheckBox", "Do not display IDA 6.x info next time") in labels
                and any(c == "TStaticText" and t.startswith("Welcome to the freeware edition of IDA Pro 5.0.")
                        for c, t in labels)):
            user.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
            if not user.PostMessageW(okay[0], 0x00F5, 0, 0):
                raise ctypes.WinError(ctypes.get_last_error())
            info["action"] = "Dismissed the IDA Freeware 5.0 welcome message"
        forms.append(info)
        return True

    user.EnumWindows(top, 0)
    return forms


def run_ida(cmd, work):
    with subprocess.Popen(cmd, cwd=work) as proc:
        last_forms = None
        for _ in range(25):
            try:
                return proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                forms = windows_for_pid(proc.pid)
                if forms != last_forms:
                    print("IDA startup windows:", forms, flush=True)
                    last_forms = forms
        proc.kill()
        proc.wait(timeout=10)
        log = work / "ida.log"
        detail = log.read_text(errors="replace")[-2500:] if log.is_file() else "no log"
        raise RuntimeError(f"IDA timed out; windows={last_forms!r}, log={detail}")


