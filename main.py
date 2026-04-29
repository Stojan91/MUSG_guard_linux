import json
import tkinter as tk
from tkinter import messagebox
from agent import LocalProtectionAgent

BG = "#090714"
PANEL = "#17162c"
BORDER = "#2c2857"
FG = "#f5f7ff"
MUTED = "#9ea7d6"
ACCENT = "#23e7ff"
PURPLE = "#8b4dff"
WARN = "#ffb84d"
OK = "#43f5a7"
DANGER = "#ff6270"


class ToastManager:
    COLORS = {
        "ok": {"bg": "#10261b", "border": "#2e8f5d", "fg": "#eafff2"},
        "warn": {"bg": "#2a2110", "border": "#b9822c", "fg": "#fff3d9"},
        "drop": {"bg": "#311218", "border": "#b33b4f", "fg": "#ffe4e9"},
        "accent": {"bg": "#102430", "border": "#2f88a8", "fg": "#e2f7ff"},
    }

    def __init__(self, root):
        self.root = root
        self.toasts = []
        self.toast_map = {}
        self.margin = 18
        self.gap = 10
        self.width = 360
        self.base_height = 102

    def _remove_dead(self):
        alive = []
        for toast in self.toasts:
            win = toast.get("window")
            try:
                if win and win.winfo_exists():
                    alive.append(toast)
            except Exception:
                pass
        self.toasts = alive
        self.toast_map = {t["group_key"]: t for t in self.toasts if t.get("group_key")}

    def _position_toasts(self):
        self._remove_dead()
        self.root.update_idletasks()
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        taskbar_pad = 54
        y = screen_h - self.margin - taskbar_pad
        for toast in reversed(self.toasts):
            win = toast["window"]
            win.update_idletasks()
            height = win.winfo_height() or toast.get("height", self.base_height)
            x = screen_w - self.width - self.margin
            y = y - height
            win.geometry(f"{self.width}x{height}+{x}+{y}")
            y = y - self.gap

    def _destroy_toast(self, toast):
        win = toast.get("window")
        if win and win.winfo_exists():
            win.destroy()
        self._remove_dead()
        self._position_toasts()

    def show(self, title, message, severity="warn", group_key=None, replace=False, count=1, duration_ms=5200, max_toasts=3):
        self._remove_dead()
        if replace and group_key in self.toast_map:
            toast = self.toast_map[group_key]
            toast["title_label"].config(text=title)
            toast["message_label"].config(text=message)
            toast["count_label"].config(text=f"x{count}" if count > 1 else "")
            if toast.get("timer"):
                self.root.after_cancel(toast["timer"])
            toast["timer"] = self.root.after(duration_ms, lambda t=toast: self._destroy_toast(t))
            self._position_toasts()
            return
        while len(self.toasts) >= max_toasts:
            oldest = self.toasts.pop(0)
            win = oldest.get("window")
            if win and win.winfo_exists():
                win.destroy()
        colors = self.COLORS.get(severity, self.COLORS["warn"])
        win = tk.Toplevel(self.root)
        win.overrideredirect(True)
        win.attributes("-topmost", True)
        win.configure(bg=colors["border"])
        try:
            win.attributes("-alpha", 0.97)
        except Exception:
            pass
        outer = tk.Frame(win, bg=colors["border"])
        outer.pack(fill="both", expand=True)
        inner = tk.Frame(outer, bg=colors["bg"])
        inner.pack(fill="both", expand=True, padx=1, pady=1)
        head = tk.Frame(inner, bg=colors["bg"])
        head.pack(fill="x", padx=14, pady=(12, 6))
        title_label = tk.Label(head, text=title, bg=colors["bg"], fg=colors["fg"], font=("Segoe UI", 11, "bold"), anchor="w")
        title_label.pack(side="left", fill="x", expand=True)
        count_label = tk.Label(head, text=f"x{count}" if count > 1 else "", bg=colors["bg"], fg=MUTED, font=("Segoe UI", 10, "bold"))
        count_label.pack(side="right")
        message_label = tk.Label(inner, text=message, bg=colors["bg"], fg="#e8ecff", font=("Segoe UI", 10), justify="left", wraplength=self.width - 36, anchor="w")
        message_label.pack(fill="x", padx=14, pady=(0, 12))
        toast = {
            "window": win,
            "group_key": group_key,
            "title_label": title_label,
            "message_label": message_label,
            "count_label": count_label,
            "height": self.base_height,
            "timer": None,
        }
        self.toasts.append(toast)
        if group_key:
            self.toast_map[group_key] = toast
        win.update_idletasks()
        real_height = max(self.base_height, inner.winfo_reqheight() + 2)
        toast["height"] = real_height
        win.geometry(f"{self.width}x{real_height}+100+100")
        self._position_toasts()
        toast["timer"] = self.root.after(duration_ms, lambda t=toast: self._destroy_toast(t))


class DashboardView(tk.Frame):
    def __init__(self, parent, agent, run_cb, stop_cb, scan_cb, update_cb):
        super().__init__(parent, bg=BG)
        self.agent = agent
        self.run_cb = run_cb
        self.stop_cb = stop_cb
        self.scan_cb = scan_cb
        self.update_cb = update_cb
        self.cards = {}
        self._build()

    def _make_card(self, parent, title, row, col):
        box = tk.Frame(parent, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        box.grid(row=row, column=col, sticky="nsew", padx=8, pady=8)
        tk.Label(box, text=title, bg=PANEL, fg=MUTED, font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=18, pady=(16, 6))
        value = tk.Label(box, text="-", bg=PANEL, fg=FG, font=("Arial", 22, "bold"))
        value.pack(anchor="w", padx=18)
        note = tk.Label(box, text="", bg=PANEL, fg="#7f87b5", font=("Segoe UI", 10), wraplength=240, justify="left")
        note.pack(anchor="w", padx=18, pady=(6, 18))
        self.cards[title] = (value, note)

    def _build(self):
        tk.Label(self, text="Musg Guard Dashboard", bg=BG, fg=ACCENT, font=("Arial", 28, "bold")).pack(anchor="w", padx=24, pady=(24, 8))
        tk.Label(self, text="Lokalny agent ochrony z ClamAV, fallbackiem i własnymi toastami GUI.", bg=BG, fg="#d7ddff", font=("Segoe UI", 13)).pack(anchor="w", padx=24)
        actions = tk.Frame(self, bg=BG)
        actions.pack(fill="x", padx=24, pady=18)
        tk.Button(actions, text="Run", command=self.run_cb, bg=PURPLE, fg="white", relief="flat", bd=0, font=("Segoe UI", 12, "bold"), padx=20, pady=10).pack(side="left")
        tk.Button(actions, text="Stop", command=self.stop_cb, bg="#241f44", fg=FG, relief="flat", bd=0, font=("Segoe UI", 12, "bold"), padx=20, pady=10).pack(side="left", padx=10)
        tk.Button(actions, text="Skanuj teraz", command=self.scan_cb, bg=PANEL, fg=FG, relief="flat", bd=0, font=("Segoe UI", 12, "bold"), padx=20, pady=10).pack(side="left")
        tk.Button(actions, text="Aktualizuj sygnatury", command=self.update_cb, bg="#103040", fg="#d8fbff", relief="flat", bd=0, font=("Segoe UI", 12, "bold"), padx=20, pady=10).pack(side="left", padx=10)
        grid = tk.Frame(self, bg=BG)
        grid.pack(fill="x", padx=24)
        for i in range(4):
            grid.grid_columnconfigure(i, weight=1)
        self._make_card(grid, "Stan", 0, 0)
        self._make_card(grid, "Alerty", 0, 1)
        self._make_card(grid, "Ostatni skan", 0, 2)
        self._make_card(grid, "ClamAV", 0, 3)
        self._make_card(grid, "Downloads", 1, 0)
        self._make_card(grid, "Procesy", 1, 1)
        self._make_card(grid, "Połączenia", 1, 2)
        self._make_card(grid, "Blokady", 1, 3)

    def refresh(self):
        state = self.agent.get_state()
        self.cards["Stan"][0].config(text=state["status"])
        self.cards["Stan"][1].config(text="ACTIVE = guard startuje automatycznie po starcie GUI.")
        self.cards["Alerty"][0].config(text=str(state["alerts_total"]))
        self.cards["Alerty"][1].config(text="Łączna liczba alertów zapisanych przez agenta.")
        self.cards["Ostatni skan"][0].config(text=state["last_scan"])
        self.cards["Ostatni skan"][1].config(text="Czas ostatniego lokalnego skanu.")
        self.cards["ClamAV"][0].config(text=state["clamav_mode"])
        self.cards["ClamAV"][1].config(text=f"Sygnatury trafienia: {state['signature_hits']}")
        self.cards["Downloads"][0].config(text=str(state["suspicious_files"]))
        self.cards["Downloads"][1].config(text=f"Sprawdzone pliki: {state['downloads_checked']}")
        self.cards["Procesy"][0].config(text=str(state["process_hits"]))
        self.cards["Procesy"][1].config(text="Wykrycia procesów heurystyczne i sygnaturowe.")
        self.cards["Połączenia"][0].config(text=str(state["network_hits"]))
        self.cards["Połączenia"][1].config(text="Wykrycia połączeń na oznaczonych portach.")
        self.cards["Blokady"][0].config(text=str(state["blocks_total"]))
        self.cards["Blokady"][1].config(text="Proces lub połączenie zakończone przez agenta.")


class AlertsView(tk.Frame):
    COLORS = {"ok": OK, "warn": WARN, "drop": DANGER, "accent": ACCENT}

    def __init__(self, parent, agent):
        super().__init__(parent, bg=BG)
        self.agent = agent
        self._build()

    def _build(self):
        tk.Label(self, text="Alerty ochrony", bg=BG, fg=FG, font=("Segoe UI", 20, "bold")).pack(anchor="w", padx=24, pady=(24, 8))
        frame = tk.Frame(self, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        frame.pack(fill="both", expand=True, padx=24, pady=18)
        self.canvas = tk.Canvas(frame, bg=PANEL, highlightthickness=0)
        self.scroll = tk.Scrollbar(frame, orient="vertical", command=self.canvas.yview)
        self.inner = tk.Frame(self.canvas, bg=PANEL)
        self.inner.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scroll.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scroll.pack(side="right", fill="y")
        self.refresh()

    def refresh(self):
        for child in self.inner.winfo_children():
            child.destroy()
        alerts = self.agent.get_alerts()
        if not alerts:
            tk.Label(self.inner, text="Brak alertów.", bg=PANEL, fg="#c8cff9", font=("Segoe UI", 12)).pack(anchor="w", padx=18, pady=18)
            return
        for item in alerts:
            sev = item.get("severity", "warn")
            card = tk.Frame(self.inner, bg="#111325", highlightthickness=1, highlightbackground=BORDER)
            card.pack(fill="x", padx=14, pady=10)
            tk.Label(card, text=item.get("title", "Alert"), bg="#111325", fg=self.COLORS.get(sev, WARN), font=("Segoe UI", 13, "bold")).pack(anchor="w", padx=16, pady=(14, 4))
            tk.Label(card, text=item.get("details", ""), bg="#111325", fg="#e5ebff", font=("Segoe UI", 11), wraplength=960, justify="left").pack(anchor="w", padx=16)
            tk.Label(card, text=item.get("ts", ""), bg="#111325", fg="#7f87b5", font=("Consolas", 10)).pack(anchor="w", padx=16, pady=(6, 14))


class LogsView(tk.Frame):
    COLORS = {"ok": OK, "warn": WARN, "drop": DANGER, "accent": ACCENT}

    def __init__(self, parent, agent):
        super().__init__(parent, bg=BG)
        self.agent = agent
        self._build()

    def _build(self):
        tk.Label(self, text="Live console", bg=BG, fg=FG, font=("Segoe UI", 20, "bold")).pack(anchor="w", padx=24, pady=(24, 8))
        wrap = tk.Frame(self, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        wrap.pack(fill="both", expand=True, padx=24, pady=18)
        self.text = tk.Text(wrap, bg="#090b16", fg="#e5ebff", font=("Consolas", 11), relief="flat", bd=0, insertbackground="#ffffff", padx=18, pady=18)
        self.text.pack(fill="both", expand=True)
        for name, color in self.COLORS.items():
            self.text.tag_config(name, foreground=color)
        self.refresh()

    def refresh(self):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        for row in self.agent.read_logs():
            ts = row.get("ts", "")[-9:-1] if row.get("ts") else "--:--:--"
            tag = row.get("tag", "LOG")
            level = row.get("level", "ok")
            msg = row.get("message", "")
            self.text.insert("end", f"{ts} ")
            self.text.insert("end", f"[{tag}] ", (level,))
            self.text.insert("end", f"{msg}\n")
        self.text.configure(state="disabled")
        self.text.see("end")


class SettingsView(tk.Frame):
    def __init__(self, parent, agent, refresh_cb):
        super().__init__(parent, bg=BG)
        self.agent = agent
        self.refresh_cb = refresh_cb
        self._build()

    def _build(self):
        tk.Label(self, text="Ustawienia agenta", bg=BG, fg=FG, font=("Segoe UI", 20, "bold")).pack(anchor="w", padx=24, pady=(24, 8))
        wrap = tk.Frame(self, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        wrap.pack(fill="both", expand=True, padx=24, pady=18)
        self.editor = tk.Text(wrap, bg="#090b16", fg="#e5ebff", font=("Consolas", 11), relief="flat", bd=0, insertbackground="#ffffff", padx=18, pady=18)
        self.editor.pack(fill="both", expand=True)
        actions = tk.Frame(self, bg=BG)
        actions.pack(fill="x", padx=24, pady=(0, 24))
        tk.Button(actions, text="Zapisz", command=self.save, bg=PURPLE, fg="white", relief="flat", bd=0, font=("Segoe UI", 12, "bold"), padx=18, pady=10).pack(side="left")
        self.refresh()

    def refresh(self):
        self.editor.delete("1.0", "end")
        self.editor.insert("1.0", json.dumps(self.agent.config, ensure_ascii=False, indent=2))

    def save(self):
        try:
            cfg = json.loads(self.editor.get("1.0", "end"))
            self.agent.save_config(cfg)
            self.refresh_cb()
            messagebox.showinfo("Musg Guard", "Konfiguracja zapisana.")
        except Exception as exc:
            messagebox.showerror("Musg Guard", str(exc))


class MusgGuardApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Musg Guard")
        self.geometry("1420x900")
        self.minsize(1200, 780)
        self.configure(bg=BG)
        self.agent = LocalProtectionAgent()
        self.toast_manager = ToastManager(self)
        self.current = None
        self.views = {}
        self._build_shell()
        self.show_view("dashboard")
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.after(800, self.run_agent)
        self.after(700, self.poll_toasts)
        self.after(1500, self.periodic_refresh)

    def _build_shell(self):
        sidebar = tk.Frame(self, bg="#0d0b1a", width=290, highlightthickness=1, highlightbackground=BORDER)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        brand = tk.Frame(sidebar, bg="#0d0b1a")
        brand.pack(fill="x", padx=24, pady=(26, 14))
        tk.Label(brand, text="MUSG", fg=ACCENT, bg="#0d0b1a", font=("Arial", 30, "bold")).pack(anchor="w")
        tk.Label(brand, text="Musg Guard", fg=FG, bg="#0d0b1a", font=("Segoe UI", 19, "bold")).pack(anchor="w")
        tk.Label(brand, text="Lokalny agent ochrony hosta", fg=MUTED, bg="#0d0b1a", font=("Segoe UI", 10)).pack(anchor="w", pady=(6, 0))
        self.status_label = tk.Label(sidebar, text="ENGINE READY", fg=OK, bg="#0d0b1a", font=("Segoe UI", 14, "bold"))
        self.status_label.pack(anchor="w", padx=24, pady=(0, 8))
        self.av_label = tk.Label(sidebar, text="CLAMAV CHECK", fg=WARN, bg="#0d0b1a", font=("Segoe UI", 11, "bold"))
        self.av_label.pack(anchor="w", padx=24, pady=(0, 18))
        self.menu_buttons = {}
        for label, key in [("Dashboard", "dashboard"), ("Alerty", "alerts"), ("Logi", "logs"), ("Ustawienia", "settings")]:
            btn = tk.Button(sidebar, text=label, command=lambda k=key: self.show_view(k), fg=FG, bg=PANEL, activeforeground="#ffffff", activebackground="#26234d", relief="flat", bd=0, font=("Segoe UI", 12, "bold"), padx=20, pady=14, anchor="w")
            btn.pack(fill="x", padx=18, pady=7)
            self.menu_buttons[key] = btn
        quick = tk.Frame(sidebar, bg="#0d0b1a")
        quick.pack(side="bottom", fill="x", padx=20, pady=20)
        tk.Button(quick, text="Run", command=self.run_agent, bg=PURPLE, fg="white", relief="flat", bd=0, font=("Segoe UI", 12, "bold"), padx=18, pady=10).pack(fill="x")
        tk.Button(quick, text="Stop", command=self.stop_agent, bg="#241f44", fg=FG, relief="flat", bd=0, font=("Segoe UI", 12, "bold"), padx=18, pady=10).pack(fill="x", pady=(10, 0))
        tk.Button(quick, text="Skanuj teraz", command=self.scan_now, bg=PANEL, fg=FG, relief="flat", bd=0, font=("Segoe UI", 12, "bold"), padx=18, pady=10).pack(fill="x", pady=(10, 0))
        tk.Button(quick, text="Aktualizuj sygnatury", command=self.update_signatures, bg="#103040", fg="#d8fbff", relief="flat", bd=0, font=("Segoe UI", 12, "bold"), padx=18, pady=10).pack(fill="x", pady=(10, 0))
        self.main = tk.Frame(self, bg=BG)
        self.main.pack(side="left", fill="both", expand=True)
        self.views = {
            "dashboard": DashboardView(self.main, self.agent, self.run_agent, self.stop_agent, self.scan_now, self.update_signatures),
            "alerts": AlertsView(self.main, self.agent),
            "logs": LogsView(self.main, self.agent),
            "settings": SettingsView(self.main, self.agent, self.refresh_all),
        }

    def show_view(self, key):
        if self.current:
            self.current.pack_forget()
        self.current = self.views[key]
        self.current.pack(fill="both", expand=True)
        for name, btn in self.menu_buttons.items():
            btn.configure(bg="#26234d" if name == key else PANEL)
        self.refresh_all()

    def run_agent(self):
        self.agent.start()
        self.refresh_all()

    def stop_agent(self):
        self.agent.stop()
        self.refresh_all()

    def scan_now(self):
        self.agent.manual_scan()
        self.refresh_all()

    def update_signatures(self):
        ok = self.agent.update_signatures()
        if ok:
            messagebox.showinfo("Musg Guard", "Sygnatury zaktualizowane.")
        else:
            messagebox.showwarning("Musg Guard", "Nie udało się zaktualizować sygnatur. Sprawdź freshclam i logi.")
        self.refresh_all()

    def poll_toasts(self):
        for event in self.agent.pop_toast_events():
            self.toast_manager.show(
                title=event.get("title", "Musg Guard"),
                message=event.get("message", ""),
                severity=event.get("severity", "warn"),
                group_key=event.get("group_key"),
                replace=event.get("replace", False),
                count=event.get("count", 1),
                duration_ms=event.get("duration_ms", 5200),
                max_toasts=event.get("max_toasts", 3),
            )
        self.after(700, self.poll_toasts)

    def refresh_all(self):
        state = self.agent.get_state()
        self.status_label.config(text=state["status"], fg=OK if state["status"] == "ACTIVE" else WARN)
        self.av_label.config(text=f"CLAMAV {state['clamav_mode']}", fg=OK if state["clamav_ready"] else WARN)
        for view in self.views.values():
            if hasattr(view, "refresh"):
                view.refresh()

    def periodic_refresh(self):
        self.refresh_all()
        self.after(2000, self.periodic_refresh)

    def on_close(self):
        try:
            self.agent.stop()
        finally:
            self.destroy()


if __name__ == "__main__":
    app = MusgGuardApp()
    app.mainloop()
