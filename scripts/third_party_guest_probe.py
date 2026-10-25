"""Run Ubuntu's real packaged GNU hello executable inside QEMU Linux guest."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def dependencies(binary):
    result = subprocess.run(["ldd", str(binary)], capture_output=True, text=True, check=True)
    paths = set()
    for line in result.stdout.splitlines():
        for match in re.findall(r"(?<![\w])(/[^\s()]+)", line):
            if Path(match).is_file():
                paths.add(match)
        if "not found" in line:
            raise RuntimeError("missing shared dependency: " + line)
    return sorted(paths)

def assess_third_party(data, nonce, qemu_exit_code, timed_out):
    """Require challenge-bound markers and genuine GNU Hello output."""
    lines = {line.strip() for line in data.splitlines()}
    begin = ("OMNI_THIRD_PARTY_BEGIN_V1 nonce=" + nonce).encode() in lines
    exit_ok = ("OMNI_THIRD_PARTY_EXIT_V1 nonce=" + nonce + " code=0").encode() in lines
    # Require exact output framed by the guest, not incidental kernel text.
    output_begin = ("OMNI_HELLO_OUTPUT_BEGIN nonce=" + nonce).encode()
    output_end = ("OMNI_HELLO_OUTPUT_END nonce=" + nonce).encode()
    output = False
    for segment in data.split(output_begin)[1:]:
        if output_end in segment:
            payload = segment.split(output_end, 1)[0]
            output = b"Hello, world!" in {line.strip() for line in payload.splitlines()}
            if output:
                break
    banner = bool(re.search(rb"Linux version [0-9]", data))
    panic = bool(re.search(rb"Kernel panic - not syncing", data, re.I))
    passed = all((begin, exit_ok, output, banner)) and not panic and not timed_out and qemu_exit_code == 0
    return {
        "begin_observed": begin, "exit_zero_observed": exit_ok,
        "expected_output_observed": output, "kernel_banner_observed": banner,
        "kernel_panic_observed": panic,
        "status": "THIRD_PARTY_GNU_HELLO_EXECUTED_UNATTESTED" if passed else "BLOCKED",
    }


def main():
    kernel = Path("/tmp/omni-guest-boot/vmlinuz")
    hello = Path("/usr/bin/hello")
    busybox = shutil.which("busybox")
    qemu = shutil.which("qemu-system-x86_64")
    cpio = shutil.which("cpio")
    if not kernel.is_file() or not hello.is_file() or not all((busybox, qemu, cpio)):
        raise RuntimeError("real kernel, Ubuntu hello package, BusyBox, QEMU and cpio required")
    nonce = os.urandom(16).hex()
    package = subprocess.check_output(["dpkg-query", "-W", "-f=${Package} ${Version} ${Architecture}", "hello"], text=True).strip()
    out = Path("omni-third-party-evidence")
    out.mkdir(exist_ok=False)
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "root"
        (root / "bin").mkdir(parents=True)
        (root / "dev").mkdir()
        (root / "usr/bin").mkdir(parents=True)
        shutil.copy2(busybox, root / "bin/busybox")
        shutil.copy2(hello, root / "usr/bin/hello")
        deps = dependencies(hello)
        print("resolved_guest_shared_dependencies:", deps, flush=True)
        for dep in deps:
            destination = root / dep.lstrip("/")
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(dep, destination)
        # The ELF interpreter path must exist exactly as declared by PT_INTERP.
        interpreter_output = subprocess.check_output(["readelf", "-l", str(hello)], text=True)
        match = re.search(r"Requesting program interpreter:\s*([^]\s]+)", interpreter_output)
        if not match:
            raise RuntimeError("missing ELF PT_INTERP; cannot establish dynamic loader provenance")
        if match:
            interpreter = match.group(1)
            print("resolved_guest_elf_interpreter:", interpreter, flush=True)
            source = Path(interpreter)
            if not source.is_file():
                raise RuntimeError("ELF interpreter missing")
            dest = root / interpreter.lstrip("/")
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, dest)
        (root / "init").write_text(
            "#!/bin/busybox sh\n"
            "echo OMNI_THIRD_PARTY_BEGIN_V1 nonce=" + nonce + " > /dev/console\n"
            "/usr/bin/hello > /hello.stdout 2>/hello.stderr\n"
            "rc=$?\n"
            "echo OMNI_HELLO_OUTPUT_BEGIN nonce=" + nonce + " > /dev/console\n"
            "/bin/busybox cat /hello.stdout > /dev/console\n"
            "echo OMNI_HELLO_OUTPUT_END nonce=" + nonce + " > /dev/console\n"
            "/bin/busybox cat /hello.stderr > /dev/console\n"
            "echo OMNI_THIRD_PARTY_EXIT_V1 nonce=" + nonce + " code=$rc > /dev/console\n"
            "/bin/busybox poweroff -f\n"
        )
        (root / "init").chmod(0o755)
        archive = Path(td) / "guest.cpio"
        names = sorted(str(p.relative_to(root)) for p in root.rglob("*"))
        with archive.open("wb") as f:
            subprocess.run([cpio, "-o", "-H", "newc", "--quiet"], cwd=root,
                           input=("\n".join(names) + "\n").encode(), stdout=f, check=True)
        serial = out / "serial.log"
        stderr = out / "qemu-stderr.log"
        cmd = [qemu, "-nodefaults", "-display", "none", "-monitor", "none", "-nic", "none",
               "-no-reboot", "-machine", "q35,accel=tcg", "-m", "768", "-smp", "1",
               "-kernel", str(kernel), "-initrd", str(archive),
               "-append", "console=ttyS0 rdinit=/init panic=-1",
               "-serial", "file:" + str(serial)]
        with stderr.open("wb") as err:
            try:
                run = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=err, timeout=90, check=False)
                rc, timeout = run.returncode, False
            except subprocess.TimeoutExpired:
                rc, timeout = None, True
        data = serial.read_bytes() if serial.exists() else b""
        checks = assess_third_party(data, nonce, rc, timeout)
        success = checks["status"] != "BLOCKED"
        report = {
            "schema": "omni.third_party_guest.v1",
            "status": checks["status"],
            "package": package, "binary_sha256": digest(hello), "kernel_sha256": digest(kernel),
            "initramfs_sha256": digest(archive), "serial_sha256": hashlib.sha256(data).hexdigest(),
            "dependencies_sha256": {path: digest(path) for path in deps},
            "nonce": nonce, **checks, "qemu_exit_code": rc, "timed_out": timeout,
            "third_party_app_executed": success, "guest_attested": False,
            "compatibility_certified": False, "windows_app_executed": False,
        }
    (out / "summary.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    if not success:
        print("guest_serial_tail:", repr(data[-2400:]), flush=True)
        raise RuntimeError("real third-party GNU hello execution not proven")

if __name__ == "__main__":
    main()
