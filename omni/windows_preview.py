"""OMNI Windows preview: read-only file inspection, no execution."""
import hashlib
import json
import os
from pathlib import Path
import stat
import struct


def inspect_preview(path):
    path = Path(path)
    meta = path.lstat()
    if not stat.S_ISREG(meta.st_mode) or path.is_symlink() or (getattr(meta, "st_file_attributes", 0) & 0x400):
        raise ValueError("Only regular, non-reparse files can be inspected")
    # Windows Python lacks O_NOFOLLOW. This is a convenience preview, NOT a
    # security boundary for adversarial paths or concurrent file replacement.
    with path.open("rb") as stream:
        head = stream.read(4096)
        digest = hashlib.sha256(head)
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    fmt, arch = "UNKNOWN", "UNKNOWN"
    if head[:4] == b"\x7fELF" and len(head) >= 20:
        fmt = "ELF"
        arch = {62: "x86_64", 3: "x86", 183: "aarch64"}.get(
            int.from_bytes(head[18:20], "little" if head[5] == 1 else "big"), "UNKNOWN")
    elif head[:2] == b"MZ" and len(head) >= 64:
        off = struct.unpack_from("<I", head, 60)[0]
        if off + 24 <= len(head) and head[off:off+4] == b"PE\0\0":
            fmt = "PE"
            arch = {0x8664: "x86_64", 0x14c: "x86", 0xaa64: "aarch64"}.get(
                struct.unpack_from("<H", head, off + 4)[0], "UNKNOWN")
    elif head[:8] == b"\0asm\x01\0\0\0":
        fmt, arch = "WASM", "wasm32"
    return {"schema": "omni.windows_preview.v1", "name": path.name,
            "format": fmt, "architecture": arch, "bytes": meta.st_size,
            "sha256": digest.hexdigest(), "execution_authorized": False,
            "execution_performed": False, "compatibility_certified": False,
            "notice": "Read-only format identification; not compatibility or sandbox validation."}


def main():
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    window = tk.Tk()
    window.title("OMNI Preview | Explorador de aplicaciones")
    window.geometry("760x550")
    window.minsize(610, 450)
    window.configure(bg="#101827")
    heading = tk.Label(window, text="OMNI", font=("Segoe UI", 34, "bold"),
                       fg="#F1F5F9", bg="#101827")
    heading.pack(anchor="w", padx=30, pady=(22, 0))
    tk.Label(window, text="Explora aplicaciones sin ejecutarlas", font=("Segoe UI", 13),
             fg="#93C5FD", bg="#101827").pack(anchor="w", padx=32)
    output = tk.Text(window, wrap="word", font=("Consolas", 11), bg="#182437",
                     fg="#E2E8F0", relief="flat", padx=18, pady=18)
    output.pack(fill="both", expand=True, padx=30, pady=20)
    output.insert("1.0", "Selecciona un archivo .exe, .dll, ELF o .wasm para inspeccionarlo.\n\n"
                  "Esta versión no ejecuta aplicaciones ni modifica tu sistema.")
    output.configure(state="disabled")

    def choose():
        filename = filedialog.askopenfilename(title="Seleccionar archivo para analizar")
        if not filename:
            return
        try:
            data = inspect_preview(filename)
        except (OSError, ValueError) as exc:
            messagebox.showerror("OMNI | Inspección fallida", str(exc))
            return
        output.configure(state="normal")
        output.delete("1.0", "end")
        output.insert("1.0", json.dumps(data, indent=2, ensure_ascii=False))
        output.configure(state="disabled")

    ttk.Button(window, text="Seleccionar archivo", command=choose).pack(pady=(0, 25))
    window.mainloop()


if __name__ == "__main__":
    main()
