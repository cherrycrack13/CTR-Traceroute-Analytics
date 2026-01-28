import sys
import subprocess
import re
import threading
import statistics
import requests
import time
from datetime import datetime
import customtkinter as ctk

# --- IMPORTACIÓN PARA GRÁFICOS ---
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# --- IMPORTACIÓN EXPLÍCITA PARA PYSNMP 7.X ---
try:
    from pysnmp.hlapi.v3arch import (
        SnmpEngine, CommunityData, UdpTransportTarget, 
        ContextData, ObjectType, ObjectIdentity, getCmd
    )
    SNMP_AVAILABLE = True
except ImportError:
    try:
        from pysnmp.hlapi import (
            SnmpEngine, CommunityData, UdpTransportTarget, 
            ContextData, ObjectType, ObjectIdentity, getCmd
        )
        SNMP_AVAILABLE = True
    except ImportError:
        SNMP_AVAILABLE = False
    

# --- CONFIGURACIÓN VISUAL ---
COLOR_BG = "#050505"      
COLOR_PANEL = "#111111"   
COLOR_ACCENT = "#00f2ff"  
COLOR_TTL = "#3498db" 
COLOR_ASN = "#9b59b6" 
COLOR_SNMP = "#f39c12" 
COLOR_GOOD = "#00ff7f"    
COLOR_WARN = "#ffea00"    
COLOR_CRIT = "#ff003c"    
COLOR_DIM = "#555555"

FONT_DATA = ("Consolas", 12)  
FONT_HEAD = ("Segoe UI", 11, "bold")

class MTRApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("CTR - TOOL TRACEROUTE & ANALYTICS BY CHERRYCRACK")
        # --- AJUSTE DE ALTO INICIAL COMPACTO (CRECERÁ CON LOS RESULTADOS) ---
        self.geometry("1280x380") 
        self.configure(fg_color=COLOR_BG)
        
        self.history = {}
        self.is_running = False
        self.start_time = 0
        self.spinner_chars = ["○", "◔", "◑", "◕", "●"]
        self.spinner_state = 0
        
        self.ping_data = []
        self.jit_data = []
        self.time_axis = []
        self.last_ping_val = None

        # --- UI LAYOUT ---
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1) 

        # 1. Panel Control
        self.ctrl_frame = ctk.CTkFrame(self, fg_color=COLOR_PANEL, corner_radius=15, border_width=1, border_color="#333")
        self.ctrl_frame.grid(row=0, column=0, padx=20, pady=20, sticky="ew")

        self.status_container = ctk.CTkFrame(self.ctrl_frame, fg_color="transparent")
        self.status_container.pack(side="left", padx=10)
        self.lbl_spinner = ctk.CTkLabel(self.status_container, text="●", font=("Consolas", 28), text_color="#222")
        self.lbl_spinner.pack(side="top")
        self.lbl_timer = ctk.CTkLabel(self.status_container, text="00:00", font=("Consolas", 11), text_color="#555")
        self.lbl_timer.pack(side="top")

        self.entry_target = ctk.CTkEntry(self.ctrl_frame, placeholder_text="IP o Dominio...", width=200, height=40, font=FONT_DATA)
        self.entry_target.pack(side="left", padx=10)
        self.entry_target.bind("<Return>", lambda event: self.toggle_mtr())
        
        self.combo_proto = ctk.CTkComboBox(self.ctrl_frame, values=["Auto", "IPv4", "IPv6"], width=90, height=40)
        self.combo_proto.set("Auto")
        self.combo_proto.pack(side="left", padx=5)

        self.btn_start = ctk.CTkButton(self.ctrl_frame, text="INICIAR", font=FONT_HEAD, fg_color="#006400", command=self.toggle_mtr)
        self.btn_start.pack(side="left", padx=5)

        self.btn_clear = ctk.CTkButton(self.ctrl_frame, text="LIMPIAR", width=80, fg_color="#555", command=self.clear_table)
        self.btn_clear.pack(side="left", padx=5)

        self.btn_copy = ctk.CTkButton(self.ctrl_frame, text="LOGS", width=80, fg_color="#34495e", command=self.copy_report)
        self.btn_copy.pack(side="left", padx=5)

        self.lbl_ping = ctk.CTkLabel(self.ctrl_frame, text="PING: -- ms", font=("Consolas", 14, "bold"), text_color="#888")
        self.lbl_ping.pack(side="left", padx=15)
        self.lbl_jitter = ctk.CTkLabel(self.ctrl_frame, text="JIT: -- ms", font=("Consolas", 14, "bold"), text_color="#888")
        self.lbl_jitter.pack(side="left", padx=5)

        self.health_bar = ctk.CTkLabel(self.ctrl_frame, text="SISTEMA LISTO", font=FONT_HEAD, text_color="#555", width=150)
        self.health_bar.pack(side="right", padx=20)

        # 2. Gráfico (Compacto)
        self.graph_frame = ctk.CTkFrame(self, fg_color="#000", corner_radius=10, border_width=1, border_color="#222")
        self.graph_frame.grid(row=1, column=0, padx=20, pady=(0, 10), sticky="ew")
        self.setup_graph()

        # 3. Tabla
        self.table_container = ctk.CTkScrollableFrame(self, fg_color=COLOR_BG)
        self.table_container.grid(row=2, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self.setup_headers()

        self.animate_loop()

    def fetch_snmp_name(self, ttl, ip):
        if ip == "*" or not ip:
            return

        def snmp_task():
            try:
                import asyncio
                from pysnmp.hlapi.asyncio import (
                    get_cmd, SnmpEngine, CommunityData, 
                    UdpTransportTarget, ContextData, 
                    ObjectType, ObjectIdentity
                )
                
                async def run_query():
                    engine = SnmpEngine()
                    try:
                        transport = await UdpTransportTarget.create((ip, 161), timeout=1.5, retries=1)
                        result = await get_cmd(
                            engine,
                            CommunityData('inet_snmp', mpModel=1),
                            transport,
                            ContextData(),
                            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0'))
                        )
                        return result
                    finally:
                        engine.transport_dispatcher.close_dispatcher()

                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    errorIndication, errorStatus, errorIndex, varBinds = loop.run_until_complete(run_query())
                    
                    if not errorIndication and not errorStatus:
                        name_found = str(varBinds[0][1])
                    elif errorStatus:
                        name_found = "ERR_AUTH"
                    else:
                        name_found = "---"
                finally:
                    loop.run_until_complete(asyncio.sleep(0.1))
                    loop.close()

            except:
                name_found = "---"

            if ttl in self.history:
                self.history[ttl]["snmp_name"] = name_found
                self.after(0, self.update_ui)

        threading.Thread(target=snmp_task, daemon=True).start()

    def setup_graph(self):
        self.fig, self.ax1 = plt.subplots(figsize=(10, 1.6), dpi=100)
        self.fig.patch.set_facecolor('#000000')
        self.ax1.set_facecolor('#000000')
        self.ax1.set_ylabel("Ping", color=COLOR_ACCENT, fontsize=8)
        self.ax1.tick_params(axis='y', labelcolor=COLOR_ACCENT, labelsize=7)
        self.ax1.grid(True, color='#222', linestyle='--', alpha=0.3)
        self.ax2 = self.ax1.twinx()
        self.ax2.set_ylabel("Jit", color=COLOR_GOOD, fontsize=8)
        self.ax2.tick_params(axis='y', labelcolor=COLOR_GOOD, labelsize=7)
        self.line_ping, = self.ax1.plot([], [], color=COLOR_ACCENT, linewidth=1.5)
        self.line_jit, = self.ax2.plot([], [], color=COLOR_GOOD, linewidth=1, alpha=0.5)
        self.fig.tight_layout()
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.graph_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

    def fetch_asn(self, ttl, ip):
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=as", timeout=4)
            if r.status_code == 200:
                data = r.json()
                asn = data.get("as", "N/A").split(" ")[0]
                if ttl in self.history:
                    self.history[ttl]["asn"] = asn
                    self.after(0, self.update_ui)
        except: pass

    def setup_headers(self):
        self.cols_info = [
            ("TTL", 45), ("ASN", 100), ("HOST / DIRECCIÓN IP DE RED", 380), 
            ("IDENTIFICACIÓN (SNMP)", 220), ("PÉRDIDA", 80), 
            ("ENV", 55), ("ULT", 65), ("PROM", 65), ("JIT", 65), ("MIN", 65), ("MAX", 65)
        ]
        h_frame = ctk.CTkFrame(self.table_container, fg_color="#000", height=40)
        h_frame.pack(fill="x")
        for text, width in self.cols_info:
            ctk.CTkLabel(h_frame, text=text, width=width, font=FONT_HEAD, text_color="#666", anchor="center").pack(side="left", padx=2)

    def update_graph(self):
        if not self.is_running or not self.ping_data: return
        max_points = 40
        self.time_axis = list(range(len(self.ping_data)))[-max_points:]
        self.line_ping.set_data(self.time_axis, self.ping_data[-max_points:])
        self.line_jit.set_data(self.time_axis, self.jit_data[-max_points:])
        self.ax1.relim(); self.ax1.autoscale_view()
        self.ax2.relim(); self.ax2.autoscale_view()
        if len(self.time_axis) > 1: self.ax1.set_xlim(self.time_axis[0], self.time_axis[-1])
        self.canvas.draw_idle()

    def ping_monitor(self, target):
        while self.is_running:
            try:
                cmd = ["ping", "-n", "1", "-w", "1000", target]
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, creationflags=0x08000000)
                out, _ = proc.communicate()
                match = re.search(r"tiempo[=<](\d+)ms|time[=<](\d+)ms", out)
                if match:
                    ms = int(match.group(1) or match.group(2))
                    jit = abs(ms - self.last_ping_val) if self.last_ping_val is not None else 0
                    self.last_ping_val = ms
                    self.ping_data.append(ms); self.jit_data.append(jit)
                    self.after(0, lambda m=ms, j=jit: self.update_monitors_ui(m, j))
                    self.after(0, self.update_graph)
                else:
                    self.ping_data.append(0); self.jit_data.append(0)
            except: pass
            time.sleep(1)

    def update_monitors_ui(self, ms, jit):
        c_p = COLOR_GOOD if ms < 80 else (COLOR_WARN if ms < 150 else COLOR_CRIT)
        c_j = COLOR_GOOD if jit < 15 else (COLOR_WARN if jit < 40 else COLOR_CRIT)
        self.lbl_ping.configure(text=f"PING: {ms} ms", text_color=c_p)
        self.lbl_jitter.configure(text=f"JIT: {jit} ms", text_color=c_j)

    def toggle_mtr(self):
        if self.is_running:
            self.is_running = False
            self.btn_start.configure(text="INICIAR", fg_color="#006400")
        else:
            target = self.entry_target.get().strip()
            if not target: return
            self.is_running = True
            self.start_time = time.time(); self.ping_data = []; self.jit_data = [] 
            self.clear_table()
            self.btn_start.configure(text="DETENER", fg_color=COLOR_CRIT)
            threading.Thread(target=self.mtr_worker, args=(target,), daemon=True).start()
            threading.Thread(target=self.ping_monitor, args=(target,), daemon=True).start()

    def mtr_worker(self, target):
        proto_choice = self.combo_proto.get()
        cmd = ["tracert", "-d", "-h", "20"]
        if proto_choice == "IPv4":
            cmd.append("-4")
        elif proto_choice == "IPv6":
            cmd.append("-6")
        cmd.append(target)
        
        while self.is_running:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, creationflags=0x08000000)
            for line in process.stdout:
                if not self.is_running: break
                match = re.search(r"\s+(\d+)\s+(.*?ms|.*?)\s+(.*?ms|.*?)\s+(.*?ms|.*?)\s+([a-fA-F0-9:\.\*]+)", line)
                if match:
                    self.process_match(match)
                    self.after(0, self.update_ui)
                    self.after(0, self.update_health_status)
            if not self.is_running: break
            time.sleep(1)

    def process_match(self, match):
        ttl = int(match.group(1))
        ip = match.group(5).strip()
        
        # Limpieza de basura del comando tracert en español
        if ip.lower() in ["de", "tiempo", "espera", "agotado"]:
            ip = "*"
            
        raw_lats = match.groups()[1:4]
        lats = [float(re.findall(r"\d+", x)[0]) for x in raw_lats if re.findall(r"\d+", x)]
        
        if ttl not in self.history:
            self.history[ttl] = {"ip": ip, "asn": "...", "snmp_name": "...", "lats": [], "jits": [], "sent": 0, "recv": 0, "row": None}
            if ip != "*" and ("." in ip or ":" in ip):
                threading.Thread(target=self.fetch_asn, args=(ttl, ip), daemon=True).start()
                self.fetch_snmp_name(ttl, ip)
        
        h = self.history[ttl]
        h["sent"] += 3
        h["recv"] += len(lats)
        for lat in lats:
            if h["lats"]: h["jits"].append(abs(lat - h["lats"][-1]))
            h["lats"].append(lat)

    def update_ui(self):
        for ttl in sorted(self.history.keys()):
            h = self.history[ttl]
            l = h["lats"]
            loss = ((h["sent"] - h["recv"]) / h["sent"] * 100) if h["sent"] > 0 else 0
            avg = statistics.mean(l) if l else 0
            jit = statistics.mean(h["jits"]) if h["jits"] else 0
            current_val = f"{l[-1]:.0f}" if l else "0"
            min_val = f"{min(l):.0f}" if l else "0"
            max_val = f"{max(l):.0f}" if l else "0"
            
            # --- LÓGICA DE TEXTO PARA SALTOS SIN RESPUESTA ---
            display_ip = h["ip"]
            ip_text_color = "#fff" 
            
            if display_ip == "*" or loss >= 100: 
                display_ip = "HOST NO ALCANZABLE"
                ip_text_color = COLOR_CRIT 
            
            if h["row"] is None:
                h["row"] = ctk.CTkFrame(self.table_container, fg_color="#111", corner_radius=5)
                h["row"].pack(fill="x", pady=2) 
                for _, w in self.cols_info: 
                    # anchor="center" para centrar los textos en las columnas
                    ctk.CTkLabel(h["row"], text="", width=w, font=FONT_DATA, anchor="center").pack(side="left", padx=2)
                
                # --- AJUSTE DINÁMICO DE ALTURA ---
                base_height = 380
                row_height = len(self.history) * 40
                nuevo_alto = min(base_height + row_height, 950)
                self.geometry(f"1280x{nuevo_alto}")
            
            cells = h["row"].winfo_children()
            data = [ttl, h["asn"], display_ip, h["snmp_name"], f"{loss:.1f}%", h["sent"], current_val, f"{avg:.0f}", f"{jit:.1f}", min_val, max_val]
            
            colors = [
                COLOR_TTL, COLOR_ASN, ip_text_color, COLOR_SNMP, 
                (COLOR_CRIT if loss > 5 else COLOR_GOOD), "#888", 
                COLOR_GOOD, COLOR_WARN, COLOR_GOOD, "#3498db", COLOR_CRIT
            ]
            
            for i, (val, col) in enumerate(zip(data, colors)):
                if i < len(cells):
                    cells[i].configure(text=str(val), text_color=col)

    def update_health_status(self):
        if not self.history: return
        max_loss = max([((h["sent"]-h["recv"])/h["sent"]*100) for h in self.history.values()] + [0])
        self.health_bar.configure(text="ESTADO: CRÍTICO" if max_loss > 10 else "ESTADO: ESTABLE", text_color=COLOR_CRIT if max_loss > 10 else COLOR_GOOD)

    def animate_loop(self):
        if self.is_running:
            self.lbl_spinner.configure(text=self.spinner_chars[self.spinner_state % 5], text_color=COLOR_ACCENT)
            self.spinner_state += 1
            elapsed = int(time.time() - self.start_time)
            mins, secs = divmod(elapsed, 60)
            self.lbl_timer.configure(text=f"{mins:02d}:{secs:02d}")
        self.after(150, self.animate_loop)

    def copy_report(self):
        self.health_bar.configure(text="COPIADO", text_color=COLOR_ACCENT)

    def clear_table(self):
        for widget in self.table_container.winfo_children(): widget.destroy()
        self.history = {}; self.setup_headers()
        self.geometry("1280x380") # Reset de altura al limpiar

if __name__ == "__main__":
    app = MTRApp()
    app.mainloop()