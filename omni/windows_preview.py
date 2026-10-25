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
    from omni.process_manager import NativeProcessManager
    from omni.wsl2_discovery import discover_wsl2
    from omni.runtime_choices import build_runtime_overview
    from omni.wsl2_runtime import assess_elf_wsl_launch, launch_elf_wsl
    import queue
    import subprocess
    import threading
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    window = tk.Tk()
    window.title("OMNI | Biblioteca de aplicaciones")
    window.geometry("920x820")
    window.minsize(780, 660)
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
                  "Los .exe de Windows y ELF de Linux (WSL2) requieren confirmación.\n"
                  "Se ejecutan con permisos habituales: NO están aislados.")
    output.configure(state="disabled")

    catalog = tk.Listbox(window, bg="#182437", fg="#E2E8F0", selectbackground="#2563EB",
                         height=6, relief="flat", font=("Segoe UI", 10))
    catalog.pack(fill="x", padx=30, pady=(0, 10))
    runtime_status = tk.StringVar(value="Selecciona una aplicación para consultar los motores")
    tk.Label(window, textvariable=runtime_status, font=("Segoe UI", 10),
             fg="#93C5FD", bg="#101827").pack(pady=(0, 6))

    def refresh_catalog():
        catalog.delete(0, "end")
        try:
            for item in load_catalog():
                catalog.insert("end", f'{item["name"]}  ·  {item["format"]}  ·  {item["architecture"]}')
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            messagebox.showwarning("OMNI | Catálogo", str(exc))

    process_manager = NativeProcessManager()
    displayed_sessions = []
    process_status = tk.StringVar(value="Sin procesos iniciados por OMNI")
    tk.Label(window, textvariable=process_status, font=("Segoe UI", 10),
             fg="#93C5FD", bg="#101827").pack(pady=(0, 8))

    process_list = tk.Listbox(window, bg="#182437", fg="#E2E8F0",
                              selectbackground="#2563EB", height=4,
                              relief="flat", font=("Segoe UI", 10))
    process_list.pack(fill="x", padx=30, pady=(0, 10))

    def refresh_processes():
        nonlocal displayed_sessions
        rows = process_manager.snapshot()
        if rows != displayed_sessions:
            selection = process_list.curselection()
            selected_id = (displayed_sessions[selection[0]]["id"]
                           if selection and selection[0] < len(displayed_sessions) else None)
            process_list.delete(0, "end")
            for row in rows:
                state = {"running": "En ejecución", "stop_requested": "Cierre solicitado",
                         "exited": "Finalizado"}.get(row["status"], row["status"])
                suffix = (f' · código {row["exit_code"]}'
                          if row["status"] == "exited" else "")
                process_list.insert("end",
                    f'{row["name"]} · PID {row["pid"]} · {state}{suffix}')
            displayed_sessions = rows
            for index, row in enumerate(rows):
                if row["id"] == selected_id:
                    process_list.selection_set(index)
                    break
        return rows

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
            decision = build_runtime_overview(record, wsl_discovery, wsl_choice.get())
            preferred = decision["preferred_runtime"]
            runtime_status.set("Motor disponible: " + preferred if preferred else
                               "Sin motor disponible para esta aplicación")
            output.configure(state="normal")
            output.delete("1.0", "end")
            output.insert("1.0", json.dumps(
                {"application": record, "runtimes": decision},
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
            process_manager.register(record["name"], process)
            refresh_processes()
            process_status.set(f'Iniciado: {record["name"]} (PID {process.pid})')
        except (OSError, ValueError, PermissionError, json.JSONDecodeError) as exc:
            messagebox.showerror("OMNI | No se pudo abrir", str(exc))

    def stop_selected_process():
        selection = process_list.curselection()
        if not selection or selection[0] >= len(displayed_sessions):
            messagebox.showinfo("OMNI", "Selecciona un proceso iniciado por OMNI.")
            return
        row = displayed_sessions[selection[0]]
        if row["status"] == "exited":
            messagebox.showinfo("OMNI", "Este proceso ya finalizó.")
            return
        consent = messagebox.askyesno(
            "OMNI | Forzar cierre",
            f'¿Forzar el cierre de {row["name"]} (PID {row["pid"]})?\n\n'
            "Se perderán los cambios no guardados. Solo se finalizará el proceso "
            "directo; sus procesos secundarios podrían seguir abiertos.")
        if not consent:
            return
        try:
            process_manager.stop(row["id"], confirmed=True)
            refresh_processes()
        except (OSError, KeyError, PermissionError) as exc:
            messagebox.showerror("OMNI | No se pudo cerrar", str(exc))

    def show_process_diagnostics():
        selection = process_list.curselection()
        if not selection or selection[0] >= len(displayed_sessions):
            messagebox.showinfo("OMNI", "Selecciona un proceso de la lista.")
            return
        row = displayed_sessions[selection[0]]
        info = row.get("diagnostics")
        if info is None:
            messagebox.showinfo("OMNI | Diagnóstico",
                                "Este motor no dispone de captura de errores.")
            return
        tail = info["stderr_tail"].strip()
        state = ("Captura completa" if info["stderr_complete"]
                 else "Captura en curso")
        if info["stderr_truncated"]:
            state += " · inicio recortado (máximo 8 KiB)"
        if row["exit_code"] is not None:
            state += f' · código de salida {row["exit_code"]}'
        messagebox.showinfo("OMNI | Diagnóstico WSL2",
                            state + "\n\n" + (tail or "Sin mensajes de error capturados."))

    def update_process_status():
        rows = refresh_processes()
        active = sum(row["status"] != "exited" for row in rows)
        process_status.set(f"Procesos OMNI: {active} activos · {len(rows)} registrados")
        window.after(1000, update_process_status)

    wsl_results = queue.Queue()
    wsl_launch_results = queue.Queue()
    wsl_discovery = {}
    wsl_choice = tk.StringVar()

    def poll_wsl2():
        nonlocal wsl_discovery
        try:
            discovery = wsl_results.get_nowait()
        except queue.Empty:
            window.after(100, poll_wsl2)
            return
        wsl_button.configure(state="normal")
        wsl_discovery = discovery
        distros = discovery.get("wsl2_distributions", [])
        wsl_selector.configure(values=distros)
        wsl_choice.set(distros[0] if distros else "")
        wsl_launch_button.configure(state="normal" if distros else "disabled")
        try:
            record = selected_record()
            display = {"wsl2_discovery": discovery}
            if record is not None:
                display["selected_application"] = record["name"]
                display["runtimes"] = build_runtime_overview(record, discovery, wsl_choice.get())
                preferred = display["runtimes"]["preferred_runtime"]
                runtime_status.set("Motor disponible: " + preferred if preferred else
                                   "Sin motor disponible para esta aplicación")
            output.configure(state="normal")
            output.delete("1.0", "end")
            output.insert("1.0", json.dumps(display, indent=2, ensure_ascii=False))
            output.configure(state="disabled")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            messagebox.showerror("OMNI | WSL2", str(exc))

    def check_wsl2():
        wsl_button.configure(state="disabled")
        process_status.set("Detectando WSL2 (solo consulta, sin ejecutar Linux)...")

        def worker():
            try:
                wsl_results.put(discover_wsl2())
            except Exception as exc:
                # Never leave the UI blocked if the host probe fails unexpectedly.
                wsl_results.put({"status": "PROBE_ERROR", "error_type": type(exc).__name__,
                                 "execution_authorized": False, "execution_performed": False})

        threading.Thread(target=worker, daemon=True).start()
        window.after(100, poll_wsl2)

    def poll_wsl_launch():
        try:
            kind, payload = wsl_launch_results.get_nowait()
        except queue.Empty:
            window.after(100, poll_wsl_launch)
            return
        wsl_launch_button.configure(
            state="normal" if wsl_choice.get() else "disabled")
        if kind == "error":
            messagebox.showerror("OMNI | Ejecución Linux", payload)
            return
        name, distribution, process = payload
        process_manager.register(f"{name} [WSL2: {distribution}]", process)
        refresh_processes()
        process_status.set(f"Iniciado en WSL2: {name} (PID Windows {process.pid})")

    def launch_selected_wsl():
        try:
            record = selected_record()
            if record is None:
                messagebox.showinfo("OMNI", "Selecciona un ELF de la biblioteca.")
                return
            distribution = wsl_choice.get()
            decision = assess_elf_wsl_launch(record, wsl_discovery, distribution)
            if not decision["launch_available"]:
                messagebox.showwarning("OMNI | WSL2 no disponible",
                    ", ".join(decision["reasons"]))
                return
            consent = messagebox.askyesno(
                "OMNI | Confirmar ejecución en Linux",
                f'¿Ejecutar {record["name"]} en WSL2 ({distribution})?\n\n'
                f'Archivo: {record["path"]}\n\n'
                "El programa tendrá los permisos del usuario de Linux y "
                "podría acceder a archivos de Windows y a la red. WSL2 NO "
                "es un entorno aislado de seguridad. No hay garantía de "
                "compatibilidad. Cerrar wsl.exe puede dejar procesos Linux "
                "en ejecución. Usa solamente programas de confianza.")
            if not consent:
                return
            wsl_launch_button.configure(state="disabled")

            def worker():
                try:
                    process = launch_elf_wsl(record, distribution, confirmed=True)
                    wsl_launch_results.put(("ok", (record["name"], distribution, process)))
                except (OSError, ValueError, PermissionError,
                        subprocess.TimeoutExpired, UnicodeError) as exc:
                    wsl_launch_results.put(("error", str(exc)))

            threading.Thread(target=worker, daemon=True).start()
            window.after(100, poll_wsl_launch)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            messagebox.showerror("OMNI | WSL2", str(exc))

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
    ttk.Button(controls, text="Forzar cierre", command=stop_selected_process).pack(side="left", padx=6)
    ttk.Button(controls, text="Ver diagnóstico", command=show_process_diagnostics).pack(side="left", padx=6)
    wsl_button = ttk.Button(window, text="Detectar motor Linux (WSL2)", command=check_wsl2)
    wsl_button.pack(pady=(0, 8))
    wsl_selector = ttk.Combobox(window, textvariable=wsl_choice, state="readonly", width=36)
    wsl_selector.pack(pady=(0, 6))
    wsl_selector.bind("<<ComboboxSelected>>", show_selected)
    wsl_launch_button = ttk.Button(window, text="Abrir ELF en Linux (WSL2)",
                                   command=launch_selected_wsl, state="disabled")
    wsl_launch_button.pack(pady=(0, 12))
    refresh_catalog()
    update_process_status()
    window.mainloop()


if __name__ == "__main__":
    main()
