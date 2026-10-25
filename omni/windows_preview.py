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
    from omni.catalog import add_inspection, backup_catalog, load_catalog, remove_inspection
    from omni.process_manager import NativeProcessManager
    from omni.wsl2_discovery import discover_wsl2
    from omni.runtime_choices import build_runtime_overview
    from omni.launch_coordinator import launch_with_recommended_runtime
    from omni.library_health import check_catalog_integrity
    from omni.library_status import format_catalog_row, scan_catalog_statuses
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

    catalog_entries = []
    catalog_statuses = {}
    scan_revision = 0
    scan_results = queue.Queue()
    scan_lock = threading.Lock()

    def render_catalog(selected_path=None):
        if selected_path is None:
            selection = catalog.curselection()
            if selection and selection[0] < len(catalog_entries):
                selected_path = catalog_entries[selection[0]]["path"]
        catalog.delete(0, "end")
        for index, item in enumerate(catalog_entries):
            status = catalog_statuses.get(item["path"], "checking")
            catalog.insert("end", format_catalog_row(item, status))
            color = {"unchanged": "#86EFAC", "modified": "#FBBF24",
                     "missing": "#FB7185", "unavailable": "#FDA4AF"}.get(
                         status, "#CBD5E1")
            catalog.itemconfig(index, fg=color)
            if item["path"] == selected_path:
                catalog.selection_set(index)
                catalog.activate(index)

    def refresh_catalog():
        nonlocal catalog_entries, catalog_statuses, scan_revision
        selection = catalog.curselection()
        previous_path = (catalog_entries[selection[0]]["path"]
                         if selection and selection[0] < len(catalog_entries) else None)
        try:
            entries = load_catalog()
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            if messagebox.askyesno(
                "OMNI | Catálogo dañado",
                f"No se puede leer la biblioteca: {exc}\n\n"
                "¿Guardar una copia de recuperación del archivo original? "
                "No se borrará ni se reemplazará la biblioteca."):
                try:
                    backup = backup_catalog()
                    messagebox.showinfo("OMNI | Copia guardada", str(backup))
                except OSError as backup_error:
                    messagebox.showerror("OMNI | Copia fallida", str(backup_error))
            return
        catalog_entries = entries
        catalog_statuses = {}
        render_catalog(previous_path)
        scan_revision += 1
        revision = scan_revision
        snapshot = [dict(item) for item in entries]

        def worker():
            # Serialize scans so repeated imports do not create parallel
            # hashing storms. Discard results for an older catalog revision.
            with scan_lock:
                if revision != scan_revision:
                    return
                scan_results.put((revision, scan_catalog_statuses(snapshot)))

        threading.Thread(target=worker, daemon=True).start()

    def poll_catalog_scan():
        nonlocal catalog_statuses
        while True:
            try:
                revision, statuses = scan_results.get_nowait()
            except queue.Empty:
                break
            if revision == scan_revision:
                catalog_statuses = statuses
                render_catalog()
        window.after(200, poll_catalog_scan)

    launch_status = tk.StringVar(value="Listo para abrir una aplicación seleccionada")
    tk.Label(window, textvariable=launch_status, font=("Segoe UI", 10),
             fg="#E2E8F0", bg="#101827").pack(pady=(0, 6))
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
        return (catalog_entries[selection[0]]
                if selection[0] < len(catalog_entries) else None)

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
    launch_results = queue.Queue()
    integrity_results = queue.Queue()
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

    def poll_launch():
        try:
            kind, payload = launch_results.get_nowait()
        except queue.Empty:
            window.after(100, poll_launch)
            return
        launch_button.configure(state="normal")
        if kind == "error":
            launch_status.set("No se pudo iniciar la aplicación")
            messagebox.showerror("OMNI | Ejecución", payload)
            return
        name, runtime, distribution, process = payload
        label = f"{name} [WSL2: {distribution}]" if runtime == "wsl2-elf" else name
        process_manager.register(label, process)
        refresh_processes()
        launch_status.set(f"Iniciado con {runtime}: {name} (PID Windows {process.pid})")

    def launch_recommended():
        try:
            record = selected_record()
            if record is None:
                messagebox.showinfo("OMNI", "Selecciona primero una aplicación de la biblioteca.")
                return
            distribution = wsl_choice.get()
            overview = build_runtime_overview(record, wsl_discovery, distribution)
            runtime = overview["preferred_runtime"]
            if runtime is None:
                native_reasons = ", ".join(overview["native_windows"]["reasons"])
                linux_reasons = ", ".join(overview["linux_wsl2"]["reasons"])
                messagebox.showwarning("OMNI | Sin motor disponible",
                    f"Windows: {native_reasons}\n\nWSL2: {linux_reasons}")
                return
            target = ("Windows nativo" if runtime == "windows-native"
                      else f"Linux WSL2 ({distribution})")
            consent = messagebox.askyesno(
                "OMNI | Confirmar ejecución",
                f'¿Abrir {record["name"]} con {target}?\n\n'
                f'Archivo: {record["path"]}\n\n'
                "La aplicación se ejecutará con tus permisos habituales. "
                "NO hay aislamiento ni garantía de seguridad o compatibilidad. "
                "En WSL2 podría acceder a archivos de Windows y a la red; "
                "cerrar wsl.exe no garantiza detener procesos Linux secundarios. "
                "Abre solamente programas de confianza.")
            if not consent:
                return
            # The worker repeats eligibility and file-integrity checks just
            # before execution. No Tkinter calls are made outside the UI thread.
            launch_button.configure(state="disabled")
            launch_status.set(f"Preparando ejecución con {target}...")

            def worker():
                try:
                    result = launch_with_recommended_runtime(
                        record, wsl_discovery, distribution, confirmed=True)
                    launch_results.put(("ok", (record["name"], result["runtime"],
                                               distribution, result["process"])))
                except (OSError, ValueError, PermissionError,
                        subprocess.TimeoutExpired, UnicodeError) as exc:
                    launch_results.put(("error", str(exc)))
                except Exception as exc:
                    launch_results.put(("error", f"Error inesperado: {type(exc).__name__}"))

            threading.Thread(target=worker, daemon=True).start()
            window.after(100, poll_launch)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            messagebox.showerror("OMNI | Ejecución", str(exc))

    def poll_integrity():
        try:
            result = integrity_results.get_nowait()
        except queue.Empty:
            window.after(100, poll_integrity)
            return
        integrity_button.configure(state="normal")
        try:
            current = selected_record()
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            messagebox.showerror("OMNI | Integridad", str(exc))
            return
        # The user may have selected a different application while hashing.
        if current is None or current["path"] != result["path"]:
            return
        status = result["status"]
        catalog_statuses[current["path"]] = status
        render_catalog()
        descriptions = {
            "unchanged": "Archivo sin cambios desde su registro.",
            "modified": "Archivo modificado: vuelve a agregarlo para revisar la nueva versión.",
            "missing": "Archivo no encontrado: comprueba si fue movido o eliminado.",
            "unavailable": "No se puede inspeccionar este archivo de forma segura.",
        }
        launch_status.set(descriptions[status])
        output.configure(state="normal")
        output.delete("1.0", "end")
        output.insert("1.0", json.dumps(
            {"application": current, "integrity": result},
            indent=2, ensure_ascii=False))
        output.configure(state="disabled")

    def verify_selected():
        try:
            record = selected_record()
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            messagebox.showerror("OMNI | Biblioteca", str(exc))
            return
        if record is None:
            messagebox.showinfo("OMNI", "Selecciona primero una aplicación de la biblioteca.")
            return
        integrity_button.configure(state="disabled")
        launch_status.set("Verificando archivo sin modificar la biblioteca...")

        def worker():
            try:
                result = check_catalog_integrity(record)
            except Exception as exc:
                result = {"path": record["path"], "status": "unavailable",
                          "error_type": type(exc).__name__, "changed_fields": [],
                          "execution_performed": False}
            integrity_results.put(result)

        threading.Thread(target=worker, daemon=True).start()
        window.after(100, poll_integrity)

    def remove_selected():
        selection = catalog.curselection()
        if not selection:
            return
        try:
            record = selected_record()
            if record is None:
                return
            remove_inspection(record["path"])
            refresh_catalog()
            runtime_status.set("Selecciona una aplicación para consultar los motores")
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
            catalog.selection_set(0)
            catalog.activate(0)
            show_selected()
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
    launch_button = ttk.Button(controls, text="Abrir con motor recomendado", command=launch_recommended)
    launch_button.pack(side="left", padx=6)
    ttk.Button(controls, text="Forzar cierre", command=stop_selected_process).pack(side="left", padx=6)
    ttk.Button(controls, text="Ver diagnóstico", command=show_process_diagnostics).pack(side="left", padx=6)
    secondary_controls = ttk.Frame(window)
    secondary_controls.pack(pady=(0, 8))
    integrity_button = ttk.Button(secondary_controls, text="Verificar archivo", command=verify_selected)
    integrity_button.pack(side="left", padx=6)
    wsl_button = ttk.Button(secondary_controls, text="Detectar motor Linux (WSL2)", command=check_wsl2)
    wsl_button.pack(side="left", padx=6)
    wsl_selector = ttk.Combobox(window, textvariable=wsl_choice, state="readonly", width=36)
    wsl_selector.pack(pady=(0, 6))
    wsl_selector.bind("<<ComboboxSelected>>", show_selected)
    refresh_catalog()
    poll_catalog_scan()
    update_process_status()
    window.mainloop()


if __name__ == "__main__":
    main()
