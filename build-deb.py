#!/usr/bin/env python3
"""Builds dist/sentinel-audit_<version>_<arch>.deb (amd64, arm64) with no external tools."""
import gzip, io, os, subprocess, sys, tarfile, time

version = sys.argv[1]
os.makedirs("dist", exist_ok=True)
now = int(time.time())

def tar_gz(entries):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as t:
        for name, data, mode, isdir in entries:
            ti = tarfile.TarInfo(name)
            ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname, ti.mode = now, 0, 0, "root", "root", mode
            if isdir:
                ti.type = tarfile.DIRTYPE
                t.addfile(ti)
            else:
                ti.size = len(data)
                t.addfile(ti, io.BytesIO(data))
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as g:
        g.write(raw.getvalue())
    return out.getvalue()

def ar(members):
    out = b"!<arch>\n"
    for name, data in members:
        out += f"{name:<16}{now:<12}{0:<6}{0:<6}{100644:<8o}{len(data):<10}`\n".encode()
        out += data + (b"\n" if len(data) % 2 else b"")
    return out

for arch in ("amd64", "arm64"):
    binpath = f"dist/sentinel-linux-{arch}"
    subprocess.check_call(["go", "build", "-trimpath", "-ldflags", "-s -w", "-o", binpath, "."],
                          env={**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": arch})
    binary = open(binpath, "rb").read()
    readme, lic = open("README.md", "rb").read(), open("LICENSE", "rb").read()
    data = tar_gz([
        ("./usr/", b"", 0o755, True), ("./usr/bin/", b"", 0o755, True),
        ("./usr/bin/sentinel", binary, 0o755, False),
        ("./usr/share/", b"", 0o755, True), ("./usr/share/doc/", b"", 0o755, True),
        ("./usr/share/doc/sentinel-audit/", b"", 0o755, True),
        ("./usr/share/doc/sentinel-audit/README.md", readme, 0o644, False),
        ("./usr/share/doc/sentinel-audit/copyright", lic, 0o644, False),
    ])
    control = f"""Package: sentinel-audit
Version: {version}
Section: net
Priority: optional
Architecture: {arch}
Installed-Size: {(len(binary) + len(readme) + len(lic)) // 1024 + 1}
Recommends: nmap
Maintainer: Miguel Goreiro <mgoreiro@gmail.com>
Homepage: https://github.com/mgoreiro/sentinel-audit
Description: TUI para auditar la superficie expuesta de un servidor propio
 Escanea puertos, TLS, cabeceras HTTP, rutas sensibles y paneles de un
 servidor propio o autorizado y ofrece una solución para cada hallazgo.
""".encode()
    ctrl = tar_gz([("./", b"", 0o755, True), ("./control", control, 0o644, False)])
    deb = ar([("debian-binary", b"2.0\n"), ("control.tar.gz", ctrl), ("data.tar.gz", data)])
    path = f"dist/sentinel-audit_{version}_{arch}.deb"
    open(path, "wb").write(deb)
    print("ok", path, len(deb))
