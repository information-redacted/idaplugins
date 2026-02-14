import os
import ida_diskio
import idaapi
import ida_netnode
import time
import json

QFontMetrics = None
QPalette = None
try:
    from PyQt5.QtWidgets import QMainWindow, QApplication, QLabel, QWidget
    from PyQt5.QtCore import QTimer, Qt, QEvent, QObject, QPoint
    try:
        from PyQt5.QtGui import QFontMetrics as _QFontMetrics
        QFontMetrics = _QFontMetrics
    except Exception:
        QFontMetrics = None
    try:
        from PyQt5.QtGui import QPalette as _QPalette
        QPalette = _QPalette
    except Exception:
        QPalette = None
except ModuleNotFoundError:
    from PySide6.QtWidgets import QMainWindow, QApplication, QLabel, QWidget
    from PySide6.QtCore import QTimer, Qt, QEvent, QObject, QPoint
    try:
        from PySide6.QtGui import QFontMetrics as _QFontMetrics
        QFontMetrics = _QFontMetrics
    except Exception:
        QFontMetrics = None
    try:
        from PySide6.QtGui import QPalette as _QPalette
        QPalette = _QPalette
    except Exception:
        QPalette = None

NETNODE_NAME = "$ plugin time wasted"
NETNODE_DB_TIME_KEY = 0
NETNODE_DEBUG_TIME_KEY = 1

def find_ida_main_window():
    for widget in QApplication.topLevelWidgets():
        if isinstance(widget, QMainWindow) and 'IDA' in widget.windowTitle():
            return widget
    return None

def format_elapsed(seconds):
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    return f"{days:02}:{hours:02}:{minutes:02}:{secs:02}"


def ida_version_at_least(major, minor):
    try:
        ver = idaapi.get_kernel_version()
    except Exception:
        try:
            ver = idaapi.get_ida_version()
        except Exception:
            return False

    if isinstance(ver, (tuple, list)):
        try:
            return (int(ver[0]), int(ver[1])) >= (major, minor)
        except Exception:
            return False

    if isinstance(ver, int):
        try:
            major_v = (ver >> 16) & 0xFF
            minor_v = (ver >> 8) & 0xFF
            return (major_v, minor_v) >= (major, minor)
        except Exception:
            return False

    if isinstance(ver, str):
        try:
            parts = ver.split('.')
            maj = int(parts[0])
            minr = int(parts[1]) if len(parts) > 1 else 0
            return (maj, minr) >= (major, minor)
        except Exception:
            return False

    return False

def PLUGIN_ENTRY():
    return IDAStatusBarTimerPlugin()


class _SBWatcher(QObject):
    def __init__(self, plugin, *watched_widgets):
        # parent to plugin label/container (they share the same Qt thread)
        super().__init__(plugin.status_container or plugin.label)
        self.plugin = plugin
        self._watched = []
        for w in watched_widgets:
            if w is None:
                continue
            try:
                w.installEventFilter(self)
                self._watched.append(w)
            except Exception:
                pass

    def unhook(self):
        for w in list(self._watched):
            try:
                w.removeEventFilter(self)
            except Exception:
                pass
        self._watched = []

    def eventFilter(self, obj, event):
        if event.type() in (QEvent.Resize, QEvent.Move, QEvent.LayoutRequest, QEvent.Show):
            try:
                self.plugin._overlay_relayout()
            except Exception:
                pass
        return super().eventFilter(obj, event)

class IDAStatusBarTimerPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Determine how much time you've wasted staring at dissassemblers"
    help = ""
    wanted_name = "Time Wasted"
    wanted_hotkey = ""

    def __init__(self):
        self.label = None
        self.timer = None
        self.netnode = None
        self.status_container = None
        self.separator = None
        self._sb_watcher = None
        self._sb = None
        self._main = None
        # Originals captured once per main window/statusbar to avoid cumulative growth
        self._sb_original_margins = None
        self._sb_original_min_height = None
        self._sb_original_max_height = None
        self._sb_original_base_height = None
        self._sb_original_layout_alignment = None
        self._sb_original_layout_spacing = None
        self._sb_original_layout_margins = None
        self._notifies_installed = False
        self._on_open_cb = None
        self._on_close_cb = None
        self._use_overlay = False
        self._sb_full_text = ""
        self._sb_margin = 8
        self._sb_top_margin = 0
        
        self.config = {
            "stop_re_count_when_debugging": False,
            "global": True,
            "global_debug": True,
            "per_idb": True,
            "per_idb_debug": True,
            "per_session": True,
            "per_session_debug": True
        }

        self.db_elapsed = 0
        self.debug_elapsed = 0
        self.global_debug_elapsed = 0
        self.last_check = time.time()
        self.debugging = False
        self.session_start = time.time()
        self.plugin_config_path = os.path.join(ida_diskio.get_user_idadir(), "time_wasted.config.json")
        self.plugin_data_path = os.path.join(ida_diskio.get_user_idadir(), "time_wasted.global_data.json")
        self.plugin_sessions = []

    def _capture_statusbar_originals(self):
        sb = self._sb
        if not sb:
            return
        if self._sb_original_base_height is not None:
            return

        try:
            self._sb_original_margins = sb.contentsMargins()
        except Exception:
            self._sb_original_margins = None

        try:
            self._sb_original_min_height = int(sb.minimumHeight())
        except Exception:
            self._sb_original_min_height = None

        try:
            self._sb_original_max_height = int(sb.maximumHeight())
        except Exception:
            self._sb_original_max_height = None

        try:
            lay = sb.layout()
            self._sb_original_layout_alignment = int(lay.alignment()) if lay is not None else None
        except Exception:
            self._sb_original_layout_alignment = None

        try:
            lay = sb.layout()
            self._sb_original_layout_spacing = int(lay.spacing()) if lay is not None else None
        except Exception:
            self._sb_original_layout_spacing = None

        try:
            lay = sb.layout()
            self._sb_original_layout_margins = lay.contentsMargins() if lay is not None else None
        except Exception:
            self._sb_original_layout_margins = None

        # Use the *current rendered height* as the baseline. This is stable across
        # IDB reopen and avoids sizeHint caching causing cumulative growth.
        try:
            self._sb_original_base_height = int(sb.height() or sb.sizeHint().height() or 20)
        except Exception:
            self._sb_original_base_height = 20

    def _restore_statusbar(self):
        sb = self._sb
        if not sb:
            return

        if self._sb_original_margins is not None:
            try:
                om = self._sb_original_margins
                sb.setContentsMargins(om.left(), om.top(), om.right(), om.bottom())
            except Exception:
                pass

        if self._sb_original_min_height is not None:
            try:
                sb.setMinimumHeight(int(self._sb_original_min_height))
            except Exception:
                pass

        if self._sb_original_max_height is not None:
            try:
                sb.setMaximumHeight(int(self._sb_original_max_height))
            except Exception:
                pass

        if self._sb_original_layout_alignment is not None:
            try:
                lay = sb.layout()
                if lay is not None:
                    lay.setAlignment(Qt.Alignment(self._sb_original_layout_alignment))
            except Exception:
                pass

        if self._sb_original_layout_spacing is not None:
            try:
                lay = sb.layout()
                if lay is not None:
                    lay.setSpacing(int(self._sb_original_layout_spacing))
            except Exception:
                pass

        if self._sb_original_layout_margins is not None:
            try:
                lay = sb.layout()
                if lay is not None:
                    m = self._sb_original_layout_margins
                    lay.setContentsMargins(m.left(), m.top(), m.right(), m.bottom())
            except Exception:
                pass

        try:
            sb.updateGeometry()
        except Exception:
            pass

    def _teardown_ui(self):
        # Restore statusbar changes first so layout isn't "stuck".
        try:
            self._restore_statusbar()
        except Exception:
            pass

        if self._sb_watcher:
            try:
                self._sb_watcher.unhook()
            except Exception:
                pass
            try:
                self._sb_watcher.deleteLater()
            except Exception:
                pass
            self._sb_watcher = None

        if self.timer:
            try:
                self.timer.stop()
                self.timer.deleteLater()
            except Exception:
                pass
            self.timer = None

        if self.label:
            try:
                self.label.deleteLater()
            except Exception:
                pass
            self.label = None

        if self.separator:
            try:
                self.separator.deleteLater()
            except Exception:
                pass
            self.separator = None

        if self.status_container:
            try:
                self.status_container.deleteLater()
            except Exception:
                pass
            self.status_container = None

        self._use_overlay = False
        self._sb_full_text = ""
        self._sb = None
        self._main = None

    def _overlay_relayout(self):
        if not self._use_overlay:
            return
        if not self.status_container or not self.label or not self._sb or not self._main:
            return

        sb = self._sb
        main = self._main

        # Place the overlay at the statusbar position
        try:
            sb_pos = sb.mapTo(main, QPoint(0, 0))
        except Exception:
            sb_pos = QPoint(sb.x(), sb.y())

        w = sb.width()
        h = self.status_container.height()
        
        self.status_container.setGeometry(int(sb_pos.x()), int(sb_pos.y()), int(w), int(h))
        try:
            self.status_container.raise_()
        except Exception:
            pass

        margin = int(self._sb_margin)
        available = max(10, int(w) - (margin * 2))

        shown = self._sb_full_text
        if QFontMetrics is not None:
            try:
                fm = QFontMetrics(self.label.font())
                shown = fm.elidedText(self._sb_full_text, Qt.ElideMiddle, available)
            except Exception:
                shown = self._sb_full_text

        # Put the *label widget itself* at the top-right.
        self.label.setText(shown)
        try:
            self.label.setToolTip(self._sb_full_text)
        except Exception:
            pass

        try:
            self.label.adjustSize()
        except Exception:
            pass

        # Ensure the label doesn't overlap the separator line at the bottom.
        # Reserve equal gap above and below separator for centering.
        try:
            sh = int(self.separator.height() or 2) if self.separator else 0
            gap = 4  # Gap on each side of separator
            lh = max(1, int(h) - sh - int(self._sb_top_margin) - gap * 2)
            self.label.setFixedHeight(lh)
        except Exception:
            pass

        try:
            lw = min(int(self.label.sizeHint().width()), available)
        except Exception:
            lw = available

        try:
            self.label.setFixedWidth(lw)
        except Exception:
            pass

        x = max(margin, int(w) - lw - margin)
        self.label.move(int(x), int(self._sb_top_margin))
        try:
            self.label.raise_()
        except Exception:
            pass

        if self.separator:
            try:
                sh = int(self.separator.height() or 2)
                gap = 4  # Equal gap below separator
                self.separator.setGeometry(0, max(0, int(h) - sh - gap), int(w), sh)
                self.separator.show()
                self.separator.raise_()
            except Exception:
                pass

        # Ensure widgets are visible
        try:
            self.status_container.show()
            self.label.show()
        except Exception:
            pass

    def _install_notifies_once(self):
        if self._notifies_installed:
            return
        if not hasattr(idaapi, 'notify_when'):
            return

        # Keep strong refs so callbacks aren't GC'd.
        def _on_open_idb(*args):
            try:
                # UI may not be fully laid out yet; schedule for next tick.
                QTimer.singleShot(0, self._ensure_ui)
            except Exception:
                try:
                    self._ensure_ui()
                except Exception:
                    pass
            return 0

        def _on_close_idb(*args):
            try:
                self._teardown_ui()
            except Exception:
                pass
            return 0

        self._on_open_cb = _on_open_idb
        self._on_close_cb = _on_close_idb

        try:
            if hasattr(idaapi, 'NW_OPENIDB'):
                idaapi.notify_when(idaapi.NW_OPENIDB, self._on_open_cb)
            if hasattr(idaapi, 'NW_CLOSEIDB'):
                idaapi.notify_when(idaapi.NW_CLOSEIDB, self._on_close_cb)
            self._notifies_installed = True
        except Exception:
            # best-effort; not fatal
            self._notifies_installed = True

    def _ensure_ui(self):
        # If UI already exists and still attached, just relayout.
        if self._use_overlay and self.status_container and self.label and self._sb and self._main:
            try:
                self._overlay_relayout()
            except Exception:
                pass
            return

        # Otherwise, rebuild UI from scratch.
        try:
            self._teardown_ui()
        except Exception:
            pass

        # Re-run init path to create UI elements.
        try:
            self.init()
        except Exception:
            pass
    
    def load_plugin_config(self):
        if not os.path.exists(self.plugin_config_path):
            self.save_plugin_config()
            return

        try:
            with open(self.plugin_config_path, "r") as f:
                self.config = json.load(f)
        except Exception as e:
            print(f"[time_wasted] Failed to load config, using defaults: {e}")
            self.save_plugin_config()

    def save_plugin_config(self):
        try:
            with open(self.plugin_config_path, "w") as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            print(f"[time_wasted] Failed to save config: {e}")    
                
    def load_plugin_data(self):
        if os.path.exists(self.plugin_data_path):
            try:
                with open(self.plugin_data_path, "r") as f:
                    self.plugin_sessions = json.load(f)
            except Exception:
                self.plugin_sessions = []
        else:
            self.plugin_sessions = []

    def save_plugin_data(self):
        try:
            # reload before saving to get sessions saved by other instances
            if os.path.exists(self.plugin_data_path):
                with open(self.plugin_data_path, "r") as f:
                    try:
                        existing_sessions = json.load(f)
                    except Exception:
                        existing_sessions = []
            else:
                existing_sessions = []

            merged_sessions = existing_sessions + [s for s in self.plugin_sessions if s not in existing_sessions]
    
            with open(self.plugin_data_path, "w") as f:
                f.write(json.dumps(merged_sessions, indent=2))
                f.flush()
        except Exception as e:
            print("[time_wasted] Failed saving plugin time data:", e)

    def init(self):
        # If IDA calls init() more than once (e.g., close/reopen DB),
        # tear down any previous UI so we don't accumulate padding/height.
        self._install_notifies_once()
        try:
            self._teardown_ui()
        except Exception:
            pass

        self.load_plugin_config()
        if self.config["global"]:
            self.load_plugin_data()
        self.global_elapsed = sum(session.get("duration_sec", 0) for session in self.plugin_sessions)
        self.global_debug_elapsed = sum(session.get("debug_duration_sec", 0) for session in self.plugin_sessions)

        self.session_start = time.time()
        main = find_ida_main_window()
        if not main:
            print("[time_wasted] Main window not found.")
            return idaapi.PLUGIN_SKIP

        self._main = main
    
        if self.config["per_idb"]:
            self.netnode = idaapi.netnode(NETNODE_NAME, 0, 1)
            self.db_elapsed = self.netnode.altval(NETNODE_DB_TIME_KEY)
            self.debug_elapsed = self.netnode.altval(NETNODE_DEBUG_TIME_KEY)

        self.db_elapsed_start = self.db_elapsed
        self.debug_elapsed_start = self.debug_elapsed
    
        self.label = QLabel()
        self.last_check = time.time()
        self.debugging = idaapi.is_debugger_on()
    
        def update_label():
            now = time.time()
            delta = now - self.last_check
            self.last_check = now
    
            currently_debugging = idaapi.is_debugger_on()
    
            if currently_debugging:
                if not self.debugging:
                    self.debugging = True
                self.debug_elapsed += delta
                if not self.config["stop_re_count_when_debugging"]:
                    self.db_elapsed += delta
            else:
                if self.debugging:
                    self.debugging = False
                self.db_elapsed += delta
                
    
            if self.config["per_idb"]:
                self.netnode.altset(NETNODE_DB_TIME_KEY, int(self.db_elapsed))
                self.netnode.altset(NETNODE_DEBUG_TIME_KEY, int(self.debug_elapsed))
    
            session_reverse = self.db_elapsed - self.db_elapsed_start
            session_debug = self.debug_elapsed - self.debug_elapsed_start
            total_global = self.global_elapsed + int(time.time() - self.session_start)
            total_global_debug = self.global_debug_elapsed + int(session_debug)
    
            text = "Time wasted reversing"
            if self.config["global"]:
                text += f": {format_elapsed(total_global)}"
                if self.config["global_debug"]:
                    text += f" | debugging: {format_elapsed(total_global_debug)}"
            
            if self.config["per_idb"]:
                if self.config["global"]:
                    text += " ["
                else:
                    text += " "
                text += f"this idb: {format_elapsed(int(self.db_elapsed))}"
                if self.config["per_idb_debug"]:
                    text += " | "
                    if not (self.config["global"] and self.config["global_debug"]):
                        text += "debugging: "
                    text += f"{format_elapsed(int(self.debug_elapsed))}"
                if self.config["global"]:
                    text += "]"
            
            if self.config["per_session"]:
                if self.config["global"] or self.config["per_idb"]:
                    text += " ["
                text += f"this session: {format_elapsed(int(session_reverse))}"
                if self.config["per_session_debug"]:
                    text += " | "
                    if not (self.config["global"] and self.config["global_debug"]) and not (self.config["per_idb"] and self.config["per_idb_debug"]):
                        text += "debugging: "
                    text += f"{format_elapsed(int(session_debug))}"
                if self.config["global"] or self.config["per_idb"]:
                    text += " ]" 
                    
            if self._use_overlay and self.status_container:
                self._sb_full_text = text
                try:
                    self._overlay_relayout()
                except Exception:
                    pass
            else:
                self.label.setText(text)
    
        self.timer = QTimer()
        self.timer.timeout.connect(update_label)
        self.timer.start(1000)
        update_label()

        try:
            if ida_version_at_least(9, 3):
                sb = main.statusBar()
                self._sb = sb
                self._capture_statusbar_originals()

                try:
                    base_h = int(self._sb_original_base_height or sb.height() or 20)
                except Exception:
                    base_h = int(sb.height() or 20)

                # IDA/Qt styles can leave the statusbar taller than its natural row height,
                # which causes the bottom row contents to appear far from the separator.
                # Prefer sizeHint (and never increase above the cached base).
                try:
                    hint_h = int(sb.sizeHint().height() or 0)
                except Exception:
                    hint_h = 0
                if hint_h > 0:
                    try:
                        base_h = min(int(base_h), int(hint_h))
                    except Exception:
                        pass

                # Keep the gap between the overlay strip and the normal statusbar row tight.
                # Size the reserved top strip based on the label's actual font height.
                try:
                    self.label.setWordWrap(False)
                    self.label.setAlignment(Qt.AlignRight | Qt.AlignTop)
                    self.label.setContentsMargins(0, 0, 0, 0)
                except Exception:
                    pass

                try:
                    fm = self.label.fontMetrics()
                    label_h = int(fm.height() or 16)
                except Exception:
                    try:
                        self.label.adjustSize()
                        label_h = int(self.label.sizeHint().height() or self.label.height() or 16)
                    except Exception:
                        label_h = 16

                sep_h = 2
                gap = 4  # Equal gap above and below separator
                top_h = max(12, int(label_h + int(self._sb_top_margin) + gap + sep_h + gap))

                # Apply on top of the baseline (idempotent across IDB reopen)
                try:
                    sb.setMinimumHeight(int(base_h + top_h))
                except Exception:
                    pass
                try:
                    # Clamp to avoid extra vertical slack that makes the gap look huge.
                    sb.setMaximumHeight(int(base_h + top_h))
                except Exception:
                    pass

                # Keep existing widgets pinned to the bottom of the (now taller) statusbar.
                try:
                    lay = sb.layout()
                    if lay is not None:
                        lay.setAlignment(Qt.AlignBottom)
                        # Remove extra internal padding so the bottom row starts right
                        # under the reserved overlay strip.
                        lay.setSpacing(0)
                        lay.setContentsMargins(0, 0, 0, 0)
                except Exception:
                    pass

                try:
                    om = self._sb_original_margins
                    # Reduce margin slightly to account for internal layout spacing
                    margin_top = int(top_h) - 2
                    if om is not None:
                        sb.setContentsMargins(om.left(), margin_top, om.right(), om.bottom())
                    else:
                        sb.setContentsMargins(0, margin_top, 0, 0)
                except Exception:
                    pass

                container = QWidget(main)
                container.setFixedHeight(top_h)
                # geometry set in _overlay_relayout()
                self.label.setParent(container)
                # Visual separator between the top strip and the normal statusbar row.
                # Use the palette's window color, darkened a bit.
                try:
                    sep = QWidget(container)
                    sep.setFixedHeight(sep_h)
                    sep.setAttribute(Qt.WA_TransparentForMouseEvents, True)

                    line_css = "background-color: rgb(255, 255, 255); border: none;"
                    try:
                        if QPalette is not None:
                            base = sb.palette().color(QPalette.Window)
                            try:
                                line = base.darker(130)
                            except Exception:
                                line = base
                            line_css = f"background-color: rgb({line.red()}, {line.green()}, {line.blue()}); border: none;"
                    except Exception:
                        pass

                    sep.setStyleSheet(line_css)
                    self.separator = sep
                except Exception:
                    self.separator = None
                self.status_container = container
                self._use_overlay = True
                self._sb_watcher = _SBWatcher(self, main, sb)
                # initial relayout
                self._sb_full_text = self.label.text() or ""
                self._overlay_relayout()
            else:
                main.statusBar().addPermanentWidget(self.label)
        except Exception:
            main.statusBar().addPermanentWidget(self.label)
        print(f"[time_wasted] Initialized ({self.config})")
    
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    
    def term(self):
        if self.config["global"]:
            session_end = time.time()
            self.plugin_sessions.append({
                "start": self.session_start,
                "end": session_end,
                "duration_sec": int(session_end - self.session_start),
                "debug_duration_sec": int(self.debug_elapsed - self.debug_elapsed_start)
            })
            self.save_plugin_data()

        self._teardown_ui()

        if self.netnode and self.config["per_idb"]:
            self.netnode.altset(NETNODE_DB_TIME_KEY, int(self.db_elapsed))
            self.netnode.altset(NETNODE_DEBUG_TIME_KEY, int(self.debug_elapsed))
