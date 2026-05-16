"""FindingsPanel — Tab-toggled overlay showing live findings from the DB."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import ModalScreen
from textual.widgets import RichLog

from konr.storage.db import FindingsDB

SEV_COLORS = {
    "critical": "#ff0000",
    "high":     "#ff6600",
    "medium":   "#ffff00",
    "low":      "#00ff41",
    "info":     "#007733",
}


class FindingsPanel(ModalScreen[None]):
    """Full-screen findings overlay. Tab or Escape to close."""

    BINDINGS = [
        Binding("tab",    "close", "Close", show=True),
        Binding("escape", "close", "Close", show=False),
    ]

    DEFAULT_CSS = """
    FindingsPanel {
        align: center middle;
        background: rgba(0,0,0,0.85);
    }

    #findings-box {
        width: 90%;
        height: 90%;
        border: double #00ff41;
        background: #000000;
        padding: 0 1;
    }
    """

    def __init__(self, db: FindingsDB, engagement_id: int, **kwargs) -> None:
        super().__init__(**kwargs)
        self._db            = db
        self._engagement_id = engagement_id

    def compose(self) -> ComposeResult:
        log = RichLog(id="findings-box", markup=True, highlight=False, wrap=False)
        yield log

    def on_mount(self) -> None:
        self._refresh()

    def _refresh(self) -> None:
        log = self.query_one("#findings-box", RichLog)
        log.clear()
        log.write("[bold #00ff41]  FINDINGS                          [Tab] to close[/bold #00ff41]")
        log.write("[#003311]" + "─" * 70 + "[/#003311]")

        hosts = self._db.get_hosts(self._engagement_id)
        log.write("\n[bold #00ff41]HOSTS[/bold #00ff41]")
        if hosts:
            for h in hosts:
                hn = f"  ({h['hostname']})" if h.get("hostname") else ""
                os = f"  {h['os']}" if h.get("os") else ""
                log.write(
                    f"  [#003311]──[/#003311] [#00ff41]{h['ip']}[/#00ff41]"
                    f"{hn}[#007733]{os}[/#007733]"
                )
        else:
            log.write("  [#003311](none yet)[/#003311]")

        log.write("\n[bold #00ff41]SERVICES[/bold #00ff41]")
        any_svc = False
        for h in hosts:
            for svc in self._db.get_services(h["id"]):
                any_svc = True
                ver = f"  {svc['version']}" if svc.get("version") else ""
                name = svc.get("service_name") or ""
                addr = f"{h['ip']}:{svc['port']}/{svc['protocol']}"
                log.write(
                    f"  [#003311]──[/#003311] [#00ff41]{addr}[/#00ff41]"
                    f"  [#007733]{name}[/#007733][#003311]{ver}[/#003311]"
                )
        if not any_svc:
            log.write("  [#003311](none yet)[/#003311]")

        log.write("\n[bold #00ff41]VULNERABILITIES[/bold #00ff41]")
        vulns = self._db.get_vulnerabilities(self._engagement_id)
        if vulns:
            for v in vulns:
                sev   = v.get("severity", "?").lower()
                color = SEV_COLORS.get(sev, "#00ff41")
                log.write(
                    f"  [#003311]──[/#003311] [{color}][{sev.upper()}][/{color}]"
                    f"  [#00ff41]{v['title']}[/#00ff41]"
                )
        else:
            log.write("  [#003311](none yet)[/#003311]")

        log.write("\n[bold #00ff41]CREDENTIALS[/bold #00ff41]")
        creds = self._db.get_credentials(self._engagement_id)
        if creds:
            for c in creds:
                user = c.get("username") or "?"
                sec  = "*" * min(len(c.get("secret") or ""), 8)
                log.write(
                    f"  [#003311]──[/#003311] [#00ff41]{user}[/#00ff41]"
                    f"  [#003311]{sec}[/#003311]"
                )
        else:
            log.write("  [#003311](none yet)[/#003311]")

        log.write("\n[bold #ffff00]FLAGS[/bold #ffff00]")
        flags = self._db.get_flags(self._engagement_id)
        if flags:
            for f in flags:
                log.write(
                    f"  [#003311]──[/#003311]"
                    f" [bold #ffff00]★ {f['flag_value']}[/bold #ffff00]"
                )
        else:
            log.write("  [#003311](none yet)[/#003311]")

    def action_close(self) -> None:
        self.dismiss()
