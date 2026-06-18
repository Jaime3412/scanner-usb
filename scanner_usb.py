# -*- coding: utf-8 -*-
"""
Scanner de Dispositivos de Memoria
-----------------------------------
Deteta as unidades ligadas ao computador, permite escolher uma e
faz uma analise antimalware usando o motor do Microsoft Defender,
que ja vem incluido no Windows. Nao e necessario instalar nada extra.

Requer: Windows 10/11 com o Microsoft Defender ativo.
"""

import ctypes
import os
import glob
import shutil
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

kernel32 = ctypes.windll.kernel32 if os.name == "nt" else None

# Tipos de unidade devolvidos por GetDriveTypeW
DRIVE_TYPES = {
    0: "Desconhecido",
    1: "Sem raiz",
    2: "Removivel (USB / cartao)",
    3: "Disco fixo",
    4: "Unidade de rede",
    5: "CD / DVD",
    6: "Disco RAM",
}

CREATE_NO_WINDOW = 0x08000000


# --------------------------------------------------------------------------
# Funcoes auxiliares (deteccao de unidades)
# --------------------------------------------------------------------------
def get_volume_label(root):
    """Devolve a etiqueta (nome) da unidade, ex: 'PEN_TRABALHO'."""
    vol_buf = ctypes.create_unicode_buffer(1024)
    fs_buf = ctypes.create_unicode_buffer(1024)
    serial = ctypes.c_ulong()
    max_len = ctypes.c_ulong()
    flags = ctypes.c_ulong()
    ok = kernel32.GetVolumeInformationW(
        ctypes.c_wchar_p(root),
        vol_buf, ctypes.sizeof(vol_buf) // 2,
        ctypes.byref(serial),
        ctypes.byref(max_len),
        ctypes.byref(flags),
        fs_buf, ctypes.sizeof(fs_buf) // 2,
    )
    if ok:
        return vol_buf.value or "Sem etiqueta"
    return "-"


def human_size(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.0f} PB"


def list_drives(include_fixed=False):
    """Lista as unidades removiveis (e fixas, se pedido) ligadas ao PC."""
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
                size = human_size(usage.total)
                free = human_size(usage.free)
            except OSError:
                size = free = "?"
            drives.append({
                "root": root,
                "type": DRIVE_TYPES.get(dtype, "?"),
                "label": get_volume_label(root),
                "size": size,
                "free": free,
            })
    return drives


def find_mpcmdrun():
    """Localiza o executavel do motor do Microsoft Defender (MpCmdRun.exe)."""
    plat = glob.glob(
        r"C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe"
    )
    if plat:
        plat.sort(reverse=True)  # versao mais recente primeiro
        return plat[0]
    fallback = r"C:\Program Files\Windows Defender\MpCmdRun.exe"
    return fallback if os.path.exists(fallback) else None


# --------------------------------------------------------------------------
# Interface grafica
# --------------------------------------------------------------------------
class ScannerApp:
    def __init__(self, root):
        self.root = root
        self.mp = find_mpcmdrun()
        self.scanning = False

        root.title("Scanner de Dispositivos de Memoria")
        root.geometry("700x560")
        root.minsize(580, 480)

        # Cabecalho
        tk.Label(
            root, text="Scanner de Dispositivos de Memoria",
            font=("Segoe UI", 14, "bold"),
        ).pack(pady=(12, 2))
        tk.Label(
            root, text="Analise antimalware com o motor do Microsoft Defender",
            font=("Segoe UI", 9), fg="#555",
        ).pack()

        # Tabela de unidades
        cols = ("unidade", "etiqueta", "tipo", "total", "livre")
        self.tree = ttk.Treeview(root, columns=cols, show="headings", height=6)
        for c, w in zip(cols, (70, 160, 150, 90, 90)):
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="x", padx=12, pady=10)

        # Controlos
        ctrl = tk.Frame(root)
        ctrl.pack(fill="x", padx=12)
        self.show_fixed = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            ctrl, text="Mostrar tambem discos fixos / externos",
            variable=self.show_fixed, command=self.refresh,
        ).pack(side="left")
        self.scan_btn = ttk.Button(ctrl, text="Analisar", command=self.on_scan)
        self.scan_btn.pack(side="right")
        ttk.Button(ctrl, text="Atualizar lista", command=self.refresh).pack(
            side="right", padx=6
        )

        # Barra de progresso
        self.progress = ttk.Progressbar(root, mode="indeterminate")
        self.progress.pack(fill="x", padx=12, pady=(10, 4))

        # Area de relatorio
        self.output = scrolledtext.ScrolledText(
            root, height=12, font=("Consolas", 9), wrap="word"
        )
        self.output.pack(fill="both", expand=True, padx=12, pady=(4, 8))

        self.status = tk.Label(root, text="", anchor="w", fg="#555")
        self.status.pack(fill="x", padx=12, pady=(0, 8))

        if not self.mp:
            self.scan_btn.config(state="disabled")
            self._append(
                "[AVISO] Nao foi encontrado o Microsoft Defender (MpCmdRun.exe).\n"
                "Confirma que o Defender esta ativo neste computador.\n"
            )
        self.refresh()

    # ----- acoes -----
    def refresh(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        drives = list_drives(include_fixed=self.show_fixed.get())
        for d in drives:
            self.tree.insert(
                "", "end",
                values=(d["root"], d["label"], d["type"], d["size"], d["free"]),
            )
        if not drives:
            self.set_status("Nenhum dispositivo encontrado. Liga uma pen/disco e clica em Atualizar lista.")
        else:
            self.set_status(f"{len(drives)} dispositivo(s) encontrado(s). Seleciona um e clica em Analisar.")

    def on_scan(self):
        if self.scanning:
            return
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Escolhe um dispositivo", "Seleciona primeiro uma unidade da lista.")
            return
        root_path = self.tree.item(sel[0])["values"][0]
        self.scanning = True
        self.scan_btn.config(state="disabled")
        self.progress.start(12)
        self.output.delete("1.0", "end")
        self.set_status(f"A analisar {root_path} ... isto pode demorar alguns minutos.")
        threading.Thread(target=self._worker, args=(str(root_path),), daemon=True).start()

    def _worker(self, root_path):
        # ScanType 3 = analise personalizada de um ficheiro/pasta/unidade
        cmd = [self.mp, "-Scan", "-ScanType", "3", "-File", root_path]
        self._append(f">>> A analisar {root_path}\n>>> {' '.join(cmd)}\n\n")
        rc = -1
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace",
                creationflags=CREATE_NO_WINDOW,
            )
            for line in proc.stdout:
                self._append(line)
            proc.wait()
            rc = proc.returncode
        except Exception as e:
            self._append(f"\n[ERRO] {e}\n")
        self.root.after(0, self._finish, rc)

    def _finish(self, rc):
        self.progress.stop()
        self.scanning = False
        self.scan_btn.config(state="normal")
        # Codigos do MpCmdRun: 0 = limpo, 2 = ameacas encontradas
        if rc == 0:
            self.set_status("Concluido: nenhuma ameaca encontrada.")
            messagebox.showinfo("Analise concluida", "Nenhuma ameaca foi encontrada neste dispositivo.")
        elif rc == 2:
            self.set_status("ATENCAO: foram encontradas ameacas. Ver o relatorio.")
            messagebox.showwarning(
                "Ameacas encontradas",
                "Foram detetadas ameacas! O Defender tratou-as ou requer accao tua.\n"
                "Verifica o relatorio e o Centro de Seguranca do Windows.",
            )
        else:
            self.set_status(f"Terminou com codigo {rc}. Ver o relatorio.")
            messagebox.showinfo("Analise terminada", f"A analise terminou (codigo {rc}). Consulta o relatorio.")

    # ----- utilitarios de UI (seguros para threads) -----
    def _append(self, text):
        self.root.after(0, lambda: (self.output.insert("end", text), self.output.see("end")))

    def set_status(self, text):
        self.root.after(0, lambda: self.status.config(text=text))


def main():
    if os.name != "nt":
        print("Este programa so funciona no Windows.")
        return
    root = tk.Tk()
    ScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
