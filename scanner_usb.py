# -*- coding: utf-8 -*-
"""
Scanner de Dispositivos de Memoria
-----------------------------------
Deteta as unidades ligadas ao computador, mostra as pastas de cada disco,
permite analisar o disco inteiro ou apenas as pastas escolhidas (motor do
Microsoft Defender) e gravar um relatorio detalhado da analise.

Requer: Windows 10/11 com o Microsoft Defender ativo.
"""

import ctypes
from ctypes import wintypes
import os
import glob
import json
import shutil
import getpass
import platform
import subprocess
import tempfile
import threading
import time
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog

kernel32 = ctypes.windll.kernel32 if os.name == "nt" else None

if kernel32:
    kernel32.GetFileAttributesW.restype = wintypes.DWORD
    kernel32.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
    kernel32.SetFileAttributesW.restype = wintypes.BOOL
    kernel32.SetFileAttributesW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]

FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

SYSTEM_FOLDER_NAMES = {"system volume information", "$recycle.bin", "recycler", "found.000"}
SUSPICIOUS_TARGETS = ("cmd.exe", "cmd /", ".cmd", "powershell", "wscript", "cscript",
                      ".bat", ".vbs", ".js", ".scr", ".pif", "rundll32", "mshta")

DRIVE_TYPES = {
    0: "Desconhecido", 1: "Sem raiz", 2: "Removivel (USB / cartao)",
    3: "Disco fixo", 4: "Unidade de rede", 5: "CD / DVD", 6: "Disco RAM",
}

CREATE_NO_WINDOW = 0x08000000


# --------------------------------------------------------------------------
# Funcoes auxiliares
# --------------------------------------------------------------------------
def get_volume_label(root):
    vol_buf = ctypes.create_unicode_buffer(1024)
    fs_buf = ctypes.create_unicode_buffer(1024)
    serial = ctypes.c_ulong(); max_len = ctypes.c_ulong(); flags = ctypes.c_ulong()
    ok = kernel32.GetVolumeInformationW(
        ctypes.c_wchar_p(root), vol_buf, ctypes.sizeof(vol_buf) // 2,
        ctypes.byref(serial), ctypes.byref(max_len), ctypes.byref(flags),
        fs_buf, ctypes.sizeof(fs_buf) // 2,
    )
    return (vol_buf.value or "Sem etiqueta") if ok else "-"


def human_size(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.0f} PB"


def list_drives(include_fixed=False):
    drives = []
    mask = kernel32.GetLogicalDrives()
    for i in range(26):
        if not (mask & (1 << i)):
            continue
        root = f"{chr(65 + i)}:\\"
        dtype = kernel32.GetDriveTypeW(ctypes.c_wchar_p(root))
        if dtype == 2 or (include_fixed and dtype == 3):
            try:
                usage = shutil.disk_usage(root)
                size, free = human_size(usage.total), human_size(usage.free)
            except OSError:
                size = free = "?"
            drives.append({"root": root, "type": DRIVE_TYPES.get(dtype, "?"), "dtype": dtype,
                           "label": get_volume_label(root), "size": size, "free": free})
    return drives


def list_subdirs(path):
    try:
        entries = [e for e in os.scandir(path) if e.is_dir(follow_symlinks=False)]
    except (PermissionError, OSError):
        return []
    return sorted(entries, key=lambda e: e.name.lower())


def has_subdirs(path):
    try:
        with os.scandir(path) as it:
            return any(e.is_dir(follow_symlinks=False) for e in it)
    except (PermissionError, OSError):
        return False


def find_mpcmdrun():
    plat = glob.glob(r"C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe")
    if plat:
        plat.sort(reverse=True)
        return plat[0]
    fb = r"C:\Program Files\Windows Defender\MpCmdRun.exe"
    return fb if os.path.exists(fb) else None


def clean_resources(res):
    """Limpa os caminhos devolvidos pelo Defender (ex: 'file:_E:\\x.exe')."""
    if res is None:
        return []
    if isinstance(res, str):
        res = [res]
    out = []
    for r in res:
        s = str(r)
        for pref in ("file:_", "file:"):
            if s.startswith(pref):
                s = s[len(pref):]
        out.append(s)
    return out


def force_eject(letter):
    """Ultimo recurso: bloqueia, desmonta e ejeta o volume a forca.
    ATENCAO: pode causar perda de dados se houver gravacoes por terminar."""
    from ctypes import wintypes
    k = ctypes.windll.kernel32
    k.CreateFileW.restype = wintypes.HANDLE
    k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                              wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    k.DeviceIoControl.restype = wintypes.BOOL
    k.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                                  wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                  wintypes.LPVOID]
    k.CloseHandle.argtypes = [wintypes.HANDLE]

    GENERIC_RW = 0x80000000 | 0x40000000
    SHARE_RW = 0x1 | 0x2
    OPEN_EXISTING = 3
    INVALID = ctypes.c_void_p(-1).value
    FSCTL_LOCK_VOLUME = 0x00090018
    FSCTL_DISMOUNT_VOLUME = 0x00090020
    IOCTL_STORAGE_EJECT_MEDIA = 0x002D4808

    h = k.CreateFileW("\\\\.\\" + letter + ":", GENERIC_RW, SHARE_RW,
                      None, OPEN_EXISTING, 0, None)
    if not h or h == INVALID:
        return False
    br = wintypes.DWORD()
    try:
        # O lock pode falhar se houver handles abertos; ignoramos e desmontamos a forca.
        k.DeviceIoControl(h, FSCTL_LOCK_VOLUME, None, 0, None, 0, ctypes.byref(br), None)
        k.DeviceIoControl(h, FSCTL_DISMOUNT_VOLUME, None, 0, None, 0, ctypes.byref(br), None)
        ok = k.DeviceIoControl(h, IOCTL_STORAGE_EJECT_MEDIA, None, 0, None, 0, ctypes.byref(br), None)
        return bool(ok)
    except Exception:
        return False
    finally:
        k.CloseHandle(h)


def _get_attrs(path):
    return kernel32.GetFileAttributesW(path)


def is_hidden_system(path):
    a = _get_attrs(path)
    if a == INVALID_FILE_ATTRIBUTES:
        return False
    return bool(a & FILE_ATTRIBUTE_HIDDEN) and bool(a & FILE_ATTRIBUTE_SYSTEM)


def unhide(path):
    a = _get_attrs(path)
    if a == INVALID_FILE_ATTRIBUTES:
        return False
    new = a & ~FILE_ATTRIBUTE_HIDDEN & ~FILE_ATTRIBUTE_SYSTEM
    return bool(kernel32.SetFileAttributesW(path, new))


def make_deletable(path):
    kernel32.SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL)


def resolve_suspicious_lnks(lnks):
    """Resolve o alvo de cada .lnk (via WScript.Shell) e devolve so os suspeitos."""
    if not lnks:
        return []
    tmp = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
    try:
        tmp.write("\n".join(lnks))
        tmp.close()
        ps = (
            "$ws=New-Object -ComObject WScript.Shell;"
            "Get-Content -LiteralPath '" + tmp.name + "' -Encoding UTF8 | ForEach-Object {"
            "$p=$_; try{$s=$ws.CreateShortcut($p);"
            "[PSCustomObject]@{Path=$p;Target=$s.TargetPath;Args=$s.Arguments}}catch{}"
            "} | ConvertTo-Json -Depth 3"
        )
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            creationflags=CREATE_NO_WINDOW, timeout=60,
        ).stdout.strip()
    except Exception:
        out = ""
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
    if not out:
        return []
    try:
        data = json.loads(out)
    except Exception:
        return []
    if isinstance(data, dict):
        data = [data]
    suspicious = []
    for it in data:
        target = it.get("Target") or ""
        args = it.get("Args") or ""
        blob = (target + " " + args).lower()
        if any(s in blob for s in SUSPICIOUS_TARGETS):
            suspicious.append({"path": it.get("Path"), "target": target, "args": args})
    return suspicious


def scan_usb_threats(root):
    """Procura autorun.inf, atalhos suspeitos e ficheiros ocultos (raiz + 1 nivel)."""
    autoruns, lnks, hidden = [], [], []

    def inspect(path, depth):
        try:
            entries = list(os.scandir(path))
        except (PermissionError, OSError):
            return
        for e in entries:
            low = e.name.lower()
            full = e.path
            if low in SYSTEM_FOLDER_NAMES:
                continue
            if low == "autorun.inf":
                autoruns.append(full)
            elif low.endswith(".lnk"):
                lnks.append(full)
            elif is_hidden_system(full):
                hidden.append(full)
            if depth < 1:
                try:
                    if e.is_dir(follow_symlinks=False):
                        inspect(full, depth + 1)
                except OSError:
                    pass

    inspect(root, 0)
    return {"autoruns": autoruns, "shortcuts": resolve_suspicious_lnks(lnks), "hidden": hidden}


def clean_usb_threats(findings):
    """Re-mostra ficheiros ocultos, apaga autorun.inf e atalhos suspeitos."""
    res = {"unhidden": 0, "autorun_removed": 0, "shortcuts_removed": 0, "errors": []}
    for p in findings.get("hidden", []):
        if unhide(p):
            res["unhidden"] += 1
        else:
            res["errors"].append("nao mostrei: " + p)
    for p in findings.get("autoruns", []):
        try:
            make_deletable(p)
            os.remove(p)
            res["autorun_removed"] += 1
        except OSError as ex:
            res["errors"].append("autorun: " + str(ex))
    for sc in findings.get("shortcuts", []):
        p = sc.get("path")
        try:
            make_deletable(p)
            os.remove(p)
            res["shortcuts_removed"] += 1
        except OSError as ex:
            res["errors"].append("atalho: " + str(ex))
    return res


def format_volume(letter, fs, label, quick):
    """Formata a unidade via Format-Volume. Devolve (ok, mensagem)."""
    if letter.upper() == "C":
        return False, "Recusado: nao se formata o disco do sistema."
    safe_label = (label or "").replace("'", "''")
    inner = f"Format-Volume -DriveLetter {letter} -FileSystem {fs}"
    if safe_label:
        inner += f" -NewFileSystemLabel '{safe_label}'"
    if not quick:
        inner += " -Full"
    inner += " -Confirm:$false"
    ps = ("$ErrorActionPreference='Stop'; try { " + inner +
          " | Out-Null; exit 0 } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }")
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            creationflags=CREATE_NO_WINDOW, timeout=900,
        )
        if r.returncode == 0:
            return True, "Formatacao concluida."
        return False, (r.stderr or r.stdout or "Erro desconhecido").strip()
    except subprocess.TimeoutExpired:
        return False, "A formatacao demorou demasiado tempo."
    except Exception as e:
        return False, str(e)


# --------------------------------------------------------------------------
# Interface grafica
# --------------------------------------------------------------------------
class ScannerApp:
    DUMMY = "\x00dummy"

    def __init__(self, root):
        self.root = root
        self.mp = find_mpcmdrun()
        self.scanning = False
        self.proc = None
        self.cancelled = False
        self.node_paths = {}
        self.drive_info = {}
        self.current_drive = None
        self.current_drive_info = None
        self.last_report = None

        root.title("Scanner de Dispositivos de Memoria")
        root.geometry("760x800")
        root.minsize(640, 620)
        root.protocol("WM_DELETE_WINDOW", self.on_close)

        tk.Label(root, text="Scanner de Dispositivos de Memoria",
                 font=("Segoe UI", 14, "bold")).pack(pady=(12, 2))
        tk.Label(root, text="Analise antimalware com o motor do Microsoft Defender",
                 font=("Segoe UI", 9), fg="#555").pack()

        # --- Dispositivos ---
        tk.Label(root, text="Dispositivos ligados:", anchor="w",
                 font=("Segoe UI", 9, "bold")).pack(fill="x", padx=12, pady=(10, 0))
        cols = ("unidade", "etiqueta", "tipo", "total", "livre")
        self.drives = ttk.Treeview(root, columns=cols, show="headings", height=4)
        for c, w in zip(cols, (70, 150, 150, 90, 90)):
            self.drives.heading(c, text=c.capitalize())
            self.drives.column(c, width=w, anchor="w")
        self.drives.pack(fill="x", padx=12, pady=(2, 8))
        self.drives.bind("<<TreeviewSelect>>", self.on_drive_select)

        # --- Pastas ---
        tk.Label(root, text="Pastas do disco  (Ctrl+clique para escolher varias):",
                 anchor="w", font=("Segoe UI", 9, "bold")).pack(fill="x", padx=12)
        folder_frame = tk.Frame(root)
        folder_frame.pack(fill="both", expand=True, padx=12, pady=(2, 8))
        self.folders = ttk.Treeview(folder_frame, show="tree", selectmode="extended")
        vsb = ttk.Scrollbar(folder_frame, orient="vertical", command=self.folders.yview)
        self.folders.configure(yscrollcommand=vsb.set)
        self.folders.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.folders.bind("<<TreeviewOpen>>", self.on_folder_open)

        # --- Controlos de analise ---
        ctrl = tk.Frame(root)
        ctrl.pack(fill="x", padx=12)
        self.show_fixed = tk.BooleanVar(value=False)
        ttk.Checkbutton(ctrl, text="Mostrar discos fixos / externos",
                        variable=self.show_fixed, command=self.refresh).pack(side="left")
        self.cancel_btn = ttk.Button(ctrl, text="Cancelar", command=self.cancel_scan, state="disabled")
        self.cancel_btn.pack(side="right")
        self.sel_btn = ttk.Button(ctrl, text="Analisar selecionadas", command=self.on_scan_selected)
        self.sel_btn.pack(side="right", padx=6)
        self.all_btn = ttk.Button(ctrl, text="Analisar disco inteiro", command=self.on_scan_whole)
        self.all_btn.pack(side="right", padx=6)
        self.refresh_btn = ttk.Button(ctrl, text="Atualizar", command=self.refresh)
        self.refresh_btn.pack(side="right", padx=6)

        self.progress = ttk.Progressbar(root, mode="indeterminate")
        self.progress.pack(fill="x", padx=12, pady=(10, 4))

        self.output = scrolledtext.ScrolledText(root, height=8, font=("Consolas", 9), wrap="word")
        self.output.pack(fill="both", expand=True, padx=12, pady=(4, 4))

        # --- Relatorio ---
        rep = tk.Frame(root)
        rep.pack(fill="x", padx=12)
        self.eject_btn = ttk.Button(rep, text="Ejetar dispositivo", command=self.on_eject, state="disabled")
        self.eject_btn.pack(side="left")
        self.shortcut_btn = ttk.Button(rep, text="Verificar atalhos/autorun",
                                       command=self.on_check_shortcuts, state="disabled")
        self.shortcut_btn.pack(side="left", padx=6)
        self.format_btn = tk.Button(rep, text="Formatar", command=self.on_format,
                                    fg="#b00020", state="disabled")
        self.format_btn.pack(side="left", padx=6)
        self.save_btn = ttk.Button(rep, text="Guardar relatorio", command=self.save_report, state="disabled")
        self.save_btn.pack(side="right")

        self.status = tk.Label(root, text="", anchor="w", fg="#555")
        self.status.pack(fill="x", padx=12, pady=(6, 8))

        if not self.mp:
            self._disable_scan_buttons()
            self._append("[AVISO] Microsoft Defender (MpCmdRun.exe) nao encontrado.\n"
                         "Confirma que o Defender esta ativo neste computador.\n")
        self.refresh()

    # ----- dispositivos -----
    def refresh(self):
        if self.scanning:
            return
        self.drives.delete(*self.drives.get_children())
        self.folders.delete(*self.folders.get_children())
        self.node_paths.clear()
        self.drive_info.clear()
        self.current_drive = None
        self.current_drive_info = None
        drives = list_drives(include_fixed=self.show_fixed.get())
        for d in drives:
            self.drives.insert("", "end",
                               values=(d["root"], d["label"], d["type"], d["size"], d["free"]))
            self.drive_info[d["root"]] = d
        if not drives:
            self.set_status("Nenhum dispositivo encontrado. Liga uma pen/disco e clica em Atualizar.")
        else:
            self.set_status(f"{len(drives)} dispositivo(s). Seleciona um para ver as pastas.")
        self._update_eject_state()

    def on_drive_select(self, _event=None):
        if self.scanning:
            return
        sel = self.drives.selection()
        if not sel:
            return
        self.current_drive = str(self.drives.item(sel[0])["values"][0])
        self.current_drive_info = self.drive_info.get(self.current_drive)
        self._update_eject_state()
        self.populate_folders(self.current_drive)

    # ----- arvore de pastas -----
    def populate_folders(self, root_path):
        self.folders.delete(*self.folders.get_children())
        self.node_paths.clear()
        self.set_status(f"A carregar as pastas de {root_path} ...")
        self._add_children("", root_path)
        n = len(self.folders.get_children())
        self.set_status(f"{n} pasta(s) em {root_path}. Seleciona as que queres analisar.")

    def _add_children(self, parent_item, path):
        for e in list_subdirs(path):
            item = self.folders.insert(parent_item, "end", text="  " + e.name, open=False)
            self.node_paths[item] = e.path
            if has_subdirs(e.path):
                self.folders.insert(item, "end", text=self.DUMMY)

    def on_folder_open(self, _event):
        item = self.folders.focus()
        children = self.folders.get_children(item)
        if len(children) == 1 and self.folders.item(children[0], "text") == self.DUMMY:
            self.folders.delete(children[0])
            self._add_children(item, self.node_paths[item])

    # ----- analise -----
    def on_scan_whole(self):
        if not self.current_drive:
            messagebox.showinfo("Escolhe um dispositivo", "Seleciona primeiro um disco.")
            return
        self._start_scan([self.current_drive], "Disco inteiro")

    def on_scan_selected(self):
        sel = self.folders.selection()
        paths = [self.node_paths[i] for i in sel if i in self.node_paths]
        if not paths:
            messagebox.showinfo("Escolhe pastas", "Seleciona pelo menos uma pasta na arvore.")
            return
        self._start_scan(paths, f"Pastas selecionadas ({len(paths)})")

    def _start_scan(self, paths, mode):
        if self.scanning:
            return
        self.scanning = True
        self.cancelled = False
        self._scan_paths = list(paths)
        self._scan_mode = mode
        self._scan_start = datetime.now()
        self._disable_scan_buttons()
        self.save_btn.config(state="disabled")
        self.eject_btn.config(state="disabled")
        self.shortcut_btn.config(state="disabled")
        self.format_btn.config(state="disabled")
        self.cancel_btn.config(state="normal")
        self.progress.start(12)
        self.output.delete("1.0", "end")
        self.set_status(f"A analisar ({mode}) ... pode demorar.")
        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self):
        paths = self._scan_paths
        found_threats = False
        had_error = False
        log_lines = []

        def log(text):
            log_lines.append(text)
            self._append(text)

        for idx, p in enumerate(paths, 1):
            if self.cancelled:
                break
            log(f"\n===== ({idx}/{len(paths)}) A analisar: {p} =====\n")
            cmd = [self.mp, "-Scan", "-ScanType", "3", "-File", p]
            rc = -1
            try:
                self.proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, encoding="utf-8", errors="replace",
                    creationflags=CREATE_NO_WINDOW)
                for line in self.proc.stdout:
                    log(line)
                self.proc.wait()
                rc = self.proc.returncode
            except Exception as e:
                log(f"\n[ERRO] {e}\n")
            self.proc = None
            if rc == 2:
                found_threats = True
            elif rc not in (0, 2):
                had_error = True

        # Consultar o Defender pela lista estruturada de ameacas desta analise
        threats = []
        if not self.cancelled:
            for it in self.query_threats(self._scan_start):
                threats.append({
                    "name": it.get("Name") or ("ID " + str(it.get("ThreatID", "?"))),
                    "files": clean_resources(it.get("Resources")),
                })
        if threats:
            found_threats = True

        end = datetime.now()
        secs = int((end - self._scan_start).total_seconds())
        duration = f"{secs // 3600:02d}:{(secs % 3600) // 60:02d}:{secs % 60:02d}"

        if self.cancelled:
            verdict = "CANCELADO"
        elif found_threats:
            verdict = "AMEACAS ENCONTRADAS"
        elif had_error:
            verdict = "TERMINADO COM AVISOS"
        else:
            verdict = "LIMPO - nenhuma ameaca encontrada"

        self.last_report = {
            "start": self._scan_start,
            "duration": duration,
            "computer": platform.node() or "?",
            "user": getpass.getuser(),
            "engine": self.defender_version(),
            "drive": self.current_drive_info or {"root": "?", "label": "?", "type": "?", "size": "?", "free": "?"},
            "mode": self._scan_mode,
            "paths": list(paths),
            "threats": threats,
            "verdict": verdict,
            "tech_log": "".join(log_lines),
        }
        self.root.after(0, self._finish, found_threats, had_error)

    def _finish(self, found_threats, had_error):
        self.progress.stop()
        self.scanning = False
        self._enable_scan_buttons()
        self.cancel_btn.config(state="disabled")
        self._update_eject_state()
        if self.last_report:
            self.save_btn.config(state="normal")

        if self.cancelled:
            self.set_status("Analise cancelada. Podes guardar o relatorio parcial.")
            self._append("\n>>> Analise cancelada. Nada foi alterado no dispositivo.\n")
            return
        if found_threats:
            self.set_status("ATENCAO: foram encontradas ameacas. Ver o relatorio.")
            messagebox.showwarning("Ameacas encontradas",
                "Foram detetadas ameacas! Consulta o relatorio e o Centro de Seguranca do Windows.")
        elif had_error:
            self.set_status("Analise terminada com avisos. Ver o relatorio.")
            messagebox.showinfo("Analise terminada", "A analise terminou, mas houve avisos. Consulta o relatorio.")
        else:
            self.set_status("Concluido: nenhuma ameaca encontrada.")
            messagebox.showinfo("Analise concluida", "Nenhuma ameaca foi encontrada.")

    # ----- ameacas e versao -----
    def defender_version(self):
        if self.mp and "Platform" in self.mp:
            parts = self.mp.replace("/", "\\").split("\\")
            try:
                return parts[parts.index("Platform") + 1]
            except (ValueError, IndexError):
                pass
        return "desconhecida"

    def query_threats(self, since):
        """Cruza Get-MpThreatDetection com Get-MpThreat para obter nome + ficheiros."""
        since_str = since.strftime("%Y-%m-%d %H:%M:%S")
        ps = (
            "$start=[datetime]::ParseExact('" + since_str + "','yyyy-MM-dd HH:mm:ss',$null);"
            "$cat=Get-MpThreat;"
            "Get-MpThreatDetection | Where-Object {$_.InitialDetectionTime -ge $start} | ForEach-Object {"
            "$d=$_;"
            "$n=($cat | Where-Object {$_.ThreatID -eq $d.ThreatID} | Select-Object -First 1).ThreatName;"
            "[PSCustomObject]@{Name=$n;ThreatID=$d.ThreatID;Resources=$d.Resources}"
            "} | ConvertTo-Json -Depth 4"
        )
        try:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                creationflags=CREATE_NO_WINDOW, timeout=90,
            ).stdout.strip()
            if not out:
                return []
            data = json.loads(out)
            return [data] if isinstance(data, dict) else data
        except Exception:
            return []

    # ----- relatorio -----
    def build_report_text(self, r):
        d = r["drive"]
        L = []
        L.append("=" * 60)
        L.append("   RELATORIO DE ANALISE - Scanner de Dispositivos de Memoria")
        L.append("=" * 60)
        L.append(f"Data/hora:    {r['start']:%Y-%m-%d %H:%M:%S}")
        L.append(f"Duracao:      {r['duration']}")
        L.append(f"Computador:   {r['computer']}")
        L.append(f"Utilizador:   {r['user']}")
        L.append(f"Motor:        Microsoft Defender (versao {r['engine']})")
        L.append("")
        L.append("-" * 60)
        L.append("DISPOSITIVO ANALISADO")
        L.append("-" * 60)
        L.append(f"Unidade:      {d.get('root', '?')}")
        L.append(f"Etiqueta:     {d.get('label', '?')}")
        L.append(f"Tipo:         {d.get('type', '?')}")
        L.append(f"Capacidade:   {d.get('size', '?')}  (livre: {d.get('free', '?')})")
        L.append("")
        L.append("-" * 60)
        L.append("AMBITO DA ANALISE")
        L.append("-" * 60)
        L.append(f"Modo:         {r['mode']}")
        for p in r["paths"]:
            L.append(f"  - {p}")
        L.append("")
        L.append("-" * 60)
        L.append("RESULTADO")
        L.append("-" * 60)
        L.append(f"Alvos analisados:     {len(r['paths'])}")
        L.append(f"Ameacas encontradas:  {len(r['threats'])}")
        L.append(f"Veredito:             {r['verdict']}")
        if r["threats"]:
            L.append("")
            for t in r["threats"]:
                files = ", ".join(t["files"]) if t["files"] else "(ficheiro nao indicado)"
                L.append(f"  - {files}  ->  {t['name']}")
        L.append("")
        L.append("-" * 60)
        L.append("REGISTO TECNICO (saida do Microsoft Defender)")
        L.append("-" * 60)
        L.append(r["tech_log"].rstrip() or "(sem saida)")
        L.append("")
        L.append("=" * 60)
        L.append("Fim do relatorio.")
        return "\n".join(L)

    def save_report(self):
        if not self.last_report:
            messagebox.showinfo("Sem relatorio", "Faz primeiro uma analise.")
            return
        default = f"relatorio_{self.last_report['start']:%Y-%m-%d_%Hh%M}.txt"
        path = filedialog.asksaveasfilename(
            title="Guardar relatorio", defaultextension=".txt", initialfile=default,
            filetypes=[("Ficheiro de texto", "*.txt"), ("Todos os ficheiros", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.build_report_text(self.last_report))
            self.set_status(f"Relatorio guardado em {path}")
            messagebox.showinfo("Guardado", f"Relatorio guardado em:\n{path}")
        except Exception as e:
            messagebox.showerror("Erro", f"Nao foi possivel guardar o relatorio:\n{e}")

    # ----- ejetar -----
    def _update_eject_state(self):
        removable = (not self.scanning) and bool(self.current_drive_info) \
            and self.current_drive_info.get("dtype") == 2
        state = "normal" if removable else "disabled"
        self.eject_btn.config(state=state)
        self.shortcut_btn.config(state=state)
        self.format_btn.config(state=state)

    def on_eject(self):
        if self.scanning:
            return
        if not self.current_drive or not self.current_drive_info:
            messagebox.showinfo("Escolhe um dispositivo", "Seleciona primeiro um disco removivel.")
            return
        if self.current_drive_info.get("dtype") != 2:
            messagebox.showinfo("Nao removivel",
                "So e possivel ejetar dispositivos removiveis (USB / cartao).")
            return
        drive = self.current_drive
        self.eject_btn.config(state="disabled")
        self.set_status(f"A ejetar {drive} ...")
        threading.Thread(target=self._eject_worker, args=(drive,), daemon=True).start()

    def _eject_worker(self, drive):
        ok = self.eject_drive(drive)
        self.root.after(0, self._eject_done, drive, ok)

    def eject_drive(self, drive):
        """Ejeta o dispositivo da mesma forma que o 'Remover com seguranca' do Windows."""
        ps = (
            "$sh=New-Object -ComObject Shell.Application;"
            "$item=$sh.Namespace(17).Items() | Where-Object {$_.Path -eq '" + drive + "'};"
            "if($item){$item.InvokeVerb('Eject')}"
        )
        try:
            subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, text=True,
                           creationflags=CREATE_NO_WINDOW, timeout=30)
        except Exception:
            pass
        # Confirma se a unidade desapareceu (ate ~4 segundos)
        for _ in range(8):
            time.sleep(0.5)
            if drive not in [d["root"] for d in list_drives(include_fixed=True)]:
                return True
        return False

    def _eject_done(self, drive, ok):
        if ok:
            self.set_status(f"{drive} ejetado com seguranca. Ja podes remover o dispositivo.")
            messagebox.showinfo("Ejetado com seguranca",
                f"O dispositivo {drive} foi ejetado.\nJa o podes remover fisicamente.")
            self.refresh()
            return
        # Ejecao segura falhou: algo esta a usar o dispositivo.
        forcar = messagebox.askyesno("Nao foi possivel ejetar",
            f"Nao foi possivel ejetar {drive} com seguranca - algo esta a usar o dispositivo.\n\n"
            "Recomendado: fecha ficheiros e janelas do Explorador que o usem, e tenta de novo.\n\n"
            "Queres FORCAR a ejecao? ATENCAO: se houver gravacoes por terminar, podes perder dados.")
        if forcar:
            self.set_status(f"A forcar a ejecao de {drive} ...")
            threading.Thread(target=self._force_worker, args=(drive,), daemon=True).start()
        else:
            self._update_eject_state()

    def _force_worker(self, drive):
        force_eject(drive[0])
        ok = False
        for _ in range(8):
            time.sleep(0.5)
            if drive not in [d["root"] for d in list_drives(include_fixed=True)]:
                ok = True
                break
        self.root.after(0, self._force_done, drive, ok)

    def _force_done(self, drive, ok):
        if ok:
            self.set_status(f"{drive} ejetado (forcado). Ja podes remover o dispositivo.")
            messagebox.showinfo("Ejetado", f"{drive} foi ejetado a forca.\nJa o podes remover fisicamente.")
            self.refresh()
        else:
            self.set_status(f"Nao foi possivel ejetar {drive}, nem a forcar.")
            messagebox.showwarning("Falhou",
                f"Mesmo a forcar, nao foi possivel ejetar {drive}.\n"
                "Fecha este programa e remove o dispositivo, ou reinicia o computador.")
            self._update_eject_state()

    # ----- atalhos / autorun -----
    def on_check_shortcuts(self):
        if self.scanning:
            return
        if not (self.current_drive_info and self.current_drive_info.get("dtype") == 2):
            messagebox.showinfo("Nao removivel", "So para dispositivos removiveis (USB / cartao).")
            return
        drive = self.current_drive
        self.scanning = True
        self._disable_scan_buttons()
        self.eject_btn.config(state="disabled")
        self.shortcut_btn.config(state="disabled")
        self.format_btn.config(state="disabled")
        self.cancel_btn.config(state="disabled")
        self.progress.start(12)
        self.output.delete("1.0", "end")
        self.set_status(f"A verificar atalhos/autorun em {drive} ...")
        threading.Thread(target=self._shortcut_worker, args=(drive,), daemon=True).start()

    def _shortcut_worker(self, drive):
        try:
            findings = scan_usb_threats(drive)
        except Exception as e:
            findings = {"autoruns": [], "shortcuts": [], "hidden": [], "error": str(e)}
        self.root.after(0, self._shortcut_results, drive, findings)

    def _shortcut_results(self, drive, findings):
        self.progress.stop()
        self.scanning = False
        self._enable_scan_buttons()
        self._update_eject_state()

        auto = findings.get("autoruns", [])
        shorts = findings.get("shortcuts", [])
        hidden = findings.get("hidden", [])
        total = len(auto) + len(shorts) + len(hidden)

        self._append(f">>> Verificacao de atalhos/autorun em {drive}\n\n")
        if findings.get("error"):
            self._append(f"[ERRO] {findings['error']}\n\n")
        self._append(f"autorun.inf encontrados: {len(auto)}\n")
        for p in auto:
            self._append(f"  - {p}\n")
        self._append(f"\nAtalhos suspeitos: {len(shorts)}\n")
        for s in shorts:
            self._append(f"  - {s['path']}  ->  {s['target']} {s['args']}\n")
        self._append(f"\nFicheiros teus escondidos pelo virus: {len(hidden)}\n")
        for p in hidden:
            self._append(f"  - {p}\n")

        if total == 0:
            self.set_status(f"{drive} limpo: nada suspeito encontrado.")
            messagebox.showinfo("Tudo limpo",
                f"Nao foram encontrados atalhos maliciosos, autorun.inf nem ficheiros escondidos em {drive}.")
            return

        self.set_status(f"{drive}: {total} item(ns) suspeito(s). Reve a lista no relatorio.")
        msg = (f"Encontrado em {drive}:\n"
               f"  - {len(auto)} autorun.inf\n"
               f"  - {len(shorts)} atalho(s) suspeito(s)\n"
               f"  - {len(hidden)} ficheiro(s) teu(s) escondido(s)\n\n"
               "Queres LIMPAR agora?\n"
               "(volta a mostrar os teus ficheiros e apaga o autorun.inf e os atalhos maliciosos)")
        if messagebox.askyesno("Foram encontrados problemas", msg):
            self.scanning = True
            self._disable_scan_buttons()
            self.eject_btn.config(state="disabled")
            self.shortcut_btn.config(state="disabled")
            self.format_btn.config(state="disabled")
            self.progress.start(12)
            self.set_status(f"A limpar {drive} ...")
            threading.Thread(target=self._clean_worker, args=(drive, findings), daemon=True).start()

    def _clean_worker(self, drive, findings):
        try:
            res = clean_usb_threats(findings)
        except Exception as e:
            res = {"unhidden": 0, "autorun_removed": 0, "shortcuts_removed": 0, "errors": [str(e)]}
        self.root.after(0, self._clean_results, drive, res)

    def _clean_results(self, drive, res):
        self.progress.stop()
        self.scanning = False
        self._enable_scan_buttons()
        self._update_eject_state()
        self._append("\n>>> LIMPEZA CONCLUIDA\n")
        self._append(f"Ficheiros restaurados (visiveis): {res['unhidden']}\n")
        self._append(f"autorun.inf apagados: {res['autorun_removed']}\n")
        self._append(f"Atalhos apagados: {res['shortcuts_removed']}\n")
        if res["errors"]:
            self._append(f"\nAvisos ({len(res['errors'])}):\n")
            for e in res["errors"]:
                self._append(f"  - {e}\n")
        self.set_status(f"Limpeza concluida em {drive}.")
        messagebox.showinfo("Limpeza concluida",
            f"Restaurados: {res['unhidden']} ficheiro(s)\n"
            f"autorun.inf apagados: {res['autorun_removed']}\n"
            f"Atalhos apagados: {res['shortcuts_removed']}")

    # ----- formatar -----
    def on_format(self):
        if self.scanning:
            return
        if not (self.current_drive_info and self.current_drive_info.get("dtype") == 2):
            messagebox.showinfo("Nao removivel",
                "So e possivel formatar dispositivos removiveis (USB / cartao).")
            return
        FormatDialog(self.root, self, dict(self.current_drive_info))

    # ----- cancelar / fechar -----
    def cancel_scan(self):
        if self.proc and self.proc.poll() is None:
            self.cancelled = True
            self._append("\n>>> A cancelar a analise...\n")
            self._kill_proc()

    def _kill_proc(self):
        if not (self.proc and self.proc.poll() is None):
            return
        try:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(self.proc.pid)],
                           creationflags=CREATE_NO_WINDOW)
        except Exception:
            try:
                self.proc.terminate()
            except Exception:
                pass

    def on_close(self):
        if self.scanning:
            self._kill_proc()
        self.root.destroy()

    # ----- utilitarios -----
    def _disable_scan_buttons(self):
        for b in (self.sel_btn, self.all_btn, self.refresh_btn):
            b.config(state="disabled")

    def _enable_scan_buttons(self):
        for b in (self.sel_btn, self.all_btn, self.refresh_btn):
            b.config(state="normal")

    def _append(self, text):
        self.root.after(0, lambda: (self.output.insert("end", text), self.output.see("end")))

    def set_status(self, text):
        self.root.after(0, lambda: self.status.config(text=text))


class FormatDialog(tk.Toplevel):
    FILESYSTEMS = ("exFAT", "FAT32", "NTFS")

    def __init__(self, parent, app, info):
        super().__init__(parent)
        self.app = app
        self.info = info
        self.drive = info.get("root", "?")
        self.letter = self.drive[0]
        self.busy = False

        self.title("Formatar dispositivo")
        self.resizable(False, False)
        self.configure(padx=16, pady=14)
        self.grab_set()  # janela modal

        tk.Label(self, text="ATENCAO - FORMATACAO", font=("Segoe UI", 12, "bold"),
                 fg="#b00020").pack(anchor="w")
        tk.Label(self, justify="left", wraplength=430,
                 text=(f"Vais formatar a unidade {self.drive} "
                       f"({self.info.get('label', '?')}, {self.info.get('size', '?')}).\n"
                       "TODOS os dados serao APAGADOS e nao ha forma de os recuperar.")
                 ).pack(anchor="w", pady=(4, 12))

        form = tk.Frame(self)
        form.pack(fill="x")

        tk.Label(form, text="Sistema de ficheiros:").grid(row=0, column=0, sticky="w", pady=4)
        self.fs_var = tk.StringVar(value="exFAT")
        ttk.Combobox(form, textvariable=self.fs_var, values=self.FILESYSTEMS,
                     state="readonly", width=12).grid(row=0, column=1, sticky="w", padx=8)

        tk.Label(form, text="Etiqueta (nome):").grid(row=1, column=0, sticky="w", pady=4)
        lbl = self.info.get("label", "")
        if lbl in ("Sem etiqueta", "-"):
            lbl = ""
        self.label_var = tk.StringVar(value=lbl)
        tk.Entry(form, textvariable=self.label_var, width=22).grid(row=1, column=1, sticky="w", padx=8)

        self.quick_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(form, text="Formatacao rapida", variable=self.quick_var).grid(
            row=2, column=0, columnspan=2, sticky="w", pady=4)

        tk.Label(self, text=f"Para confirmar, escreve a letra da unidade ({self.letter}):",
                 fg="#b00020").pack(anchor="w", pady=(12, 2))
        self.confirm_var = tk.StringVar()
        self.confirm_var.trace_add("write", self._check_confirm)
        tk.Entry(self, textvariable=self.confirm_var, width=10).pack(anchor="w")

        self.status = tk.Label(self, text="", fg="#555")
        self.status.pack(anchor="w", pady=(8, 6))

        btns = tk.Frame(self)
        btns.pack(fill="x", pady=(4, 0))
        ttk.Button(btns, text="Cancelar", command=self._cancel).pack(side="right")
        self.fmt_btn = tk.Button(btns, text="FORMATAR", command=self._do_format,
                                 fg="#b00020", state="disabled")
        self.fmt_btn.pack(side="right", padx=8)

    def _check_confirm(self, *_):
        ok = self.confirm_var.get().strip().upper() == self.letter.upper()
        self.fmt_btn.config(state="normal" if (ok and not self.busy) else "disabled")

    def _do_format(self):
        if self.busy:
            return
        self.busy = True
        self.fmt_btn.config(state="disabled")
        self.status.config(text=f"A formatar {self.drive} ... nao remova o dispositivo.")
        threading.Thread(target=self._worker,
                         args=(self.fs_var.get(), self.label_var.get().strip(), self.quick_var.get()),
                         daemon=True).start()

    def _worker(self, fs, label, quick):
        ok, msg = format_volume(self.letter, fs, label, quick)
        self.after(0, self._done, ok, msg)

    def _done(self, ok, msg):
        self.busy = False
        if ok:
            messagebox.showinfo("Formatacao concluida",
                f"A unidade {self.drive} foi formatada com sucesso.", parent=self)
            self.app.refresh()
            self.destroy()
        else:
            self.status.config(text="Falhou.")
            messagebox.showerror("Erro ao formatar",
                f"Nao foi possivel formatar {self.drive}:\n\n{msg}\n\n"
                "Fecha ficheiros/janelas que usem o dispositivo e confirma que "
                "estas a executar como administrador.", parent=self)
            self._check_confirm()

    def _cancel(self):
        if not self.busy:
            self.destroy()


def main():
    if os.name != "nt":
        print("Este programa so funciona no Windows.")
        return
    root = tk.Tk()
    ScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
