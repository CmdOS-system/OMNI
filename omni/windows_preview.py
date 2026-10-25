"""OMNI Windows desktop: inspect files and explicitly launch native Windows EXEs."""
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
    from omni.catalog import add_inspection, load_catalog, remove_inspection
    from omni.windows_runtime import assess_native_windows, launch_native_windows
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    window = tk.Tk()
    window.title("OMNI | Biblioteca de aplicaciones")
    window.geometry("790x640")
    window.minsize(610, 450)
    window.configure(bg="#101827")
    heading = tk.Label(window, text="OMNI", font=("Segoe UI", 34, "bold"),
                       fg="#F1F5F9", bg="#101827")
    heading.pack(anchor="w", padx=30, pady=(22, 0))
    tk.Label(window, text="Explora archivos y abre aplicaciones Windows con tu permiso", font=("Segoe UI", 12),
             fg="#93C5FD", bg="#101827").pack(anchor="w", padx=32)
    output = tk.Text(window, wrap="word", font=("Consolas", 11), bg="#182437",
                     fg="#E2E8F0", relief="flat", padx=18, pady=18)
    output.pack(fill="both", expand=True, padx=30, pady=20)
    output.insert("1.0", "Selecciona un archivo .exe, .dll, ELF o .wasm para inspeccionarlo.\n\n"
                  "Solo los .exe nativos de Windows pueden abrirse con confirmación explícita.\n"
                  "Se ejecutan con tus permisos habituales: NO están aislados.")
    output.configure(state="disabled")

    catalog = tk.Listbox(window, bg="#182437", fg="#E2E8F0", selectbackground="#2563EB",
                         height=6, relief="flat", font=("Segoe UI", 10))
    catalog.pack(fill="x", padx=30, pady=(0, 10))

    def refresh_catalog():
        catalog.delete(0, "end")
        try:
            for item in load_catalog():
                catalog.insert("end", f'{item["name"]}  ·  {item["format"]}  ·  {item["architecture"]}')
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            messagebox.showwarning("OMNI | Catálogo", str(exc))

    running = []
    process_status = tk.StringVar(value="Sin procesos iniciados por OMNI")
    tk.Label(window, textvariable=process_status, font=("Segoe UI", 10),
             fg="#93C5FD", bg="#101827").pack(pady=(0, 8))

    def selected_record():
        selection = catalog.curselection()
        if not selection:
            return None
        items = load_catalog()
        return items[selection[0]] if selection[0] < len(items) else None

    def show_selected(_event=None):
        try:
            record = selected_record()
            if record is None:
                return
            decision = assess_native_windows(record)
            output.configure(state="normal")
            output.delete("1.0", "end")
            output.insert("1.0", json.dumps(
                {"application": record, "native_windows": decision},
                indent=2, ensure_ascii=False))
            output.configure(state="disabled")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            messagebox.showerror("OMNI | Biblioteca", str(exc))

    catalog.bind("<<ListboxSelect>>", show_selected)

    def launch_selected():
        try:
            record = selected_record()
            if record is None:
                messagebox.showinfo("OMNI", "Selecciona primero una aplicación de la biblioteca.")
                return
            decision = assess_native_windows(record)
            if not decision["launch_available"]:
                messagebox.showwarning("OMNI | Motor no disponible",
                    "No existe un motor configurado para abrir este archivo.\n\n"
                    + ", ".join(decision["reasons"]))
                return
            consent = messagebox.askyesno(
                "OMNI | Confirmar ejecución nativa",
                f'¿Abrir {record["name"]}?\n\nRuta: {record["path"]}\n\n'
                "Esta aplicación se ejecutará directamente en Windows con "
                "tus permisos habituales. NO hay aislamiento ni garantía "
                "de seguridad. Abre solo aplicaciones en las que confíes.")
            if not consent:
                return
            process = launch_native_windows(record, confirmed=True)
            running.append((record["name"], process))
            process_status.set(f'Iniciado: {record["name"]} (PID {process.pid})')
        except (OSError, ValueError, PermissionError, json.JSONDecodeError) as exc:
            messagebox.showerror("OMNI | No se pudo abrir", str(exc))

    def update_process_status():
        finished = [(name, proc) for name, proc in running if proc.poll() is not None]
        for name, proc in finished:
            running.remove((name, proc))
            process_status.set(f'{name} finalizó (código {proc.returncode})')
        window.after(1000, update_process_status)

    def remove_selected():
        selection = catalog.curselection()
        if not selection:
            return
        try:
            items = load_catalog()
            remove_inspection(items[selection[0]]["path"])
            refresh_catalog()
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            messagebox.showerror("OMNI | Catálogo", str(exc))

    def choose():
        filename = filedialog.askopenfilename(title="Seleccionar archivo para analizar")
        if not filename:
            return
        try:
            data = inspect_preview(filename)
        except (OSError, ValueError) as exc:
            messagebox.showerror("OMNI | Inspección fallida", str(exc))
            return
        try:
            add_inspection(filename, data)
            refresh_catalog()
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            messagebox.showwarning("OMNI | Catálogo", str(exc))
        output.configure(state="normal")
        output.delete("1.0", "end")
        output.insert("1.0", json.dumps(data, indent=2, ensure_ascii=False))
        output.configure(state="disabled")

    controls = ttk.Frame(window)
    controls.pack(pady=(0, 18))
    ttk.Button(controls, text="Seleccionar archivo", command=choose).pack(side="left", padx=6)
    ttk.Button(controls, text="Quitar de biblioteca", command=remove_selected).pack(side="left", padx=6)
    ttk.Button(controls, text="Abrir .exe de Windows", command=launch_selected).pack(side="left", padx=6)
    refresh_catalog()
    update_process_status()
    window.mainloop()


if __name__ == "__main__":
    main()
