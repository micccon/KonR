"""KonR CLI — entry point for launching an engagement."""
from __future__ import annotations

import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

import click

from konr.core import config


_WORK_KEEP = {"findings.db", "memory", "logs", "reports"}


def _clean_work_dir(work_dir: Path) -> None:
    """Remove stale tool-output files from previous engagements."""
    for item in work_dir.iterdir():
        if item.name in _WORK_KEEP:
            continue
        if item.is_dir():
            shutil.rmtree(item, ignore_errors=True)
        else:
            item.unlink(missing_ok=True)


def _check_api_key() -> None:
    if not config.ANTHROPIC_API_KEY:
        click.echo("Error: ANTHROPIC_API_KEY is not set. Export it or add it to .env", err=True)
        sys.exit(1)


@click.command()
@click.option("--target", "-t", required=True, help="Target scope: IP, CIDR range, or domain")
@click.option("--engagement", "-e", default="Engagement", show_default=True, help="Engagement name")
@click.option("--ctf", is_flag=True,
              help="CTF mode: auto-approve all actions, enable flag detection")
@click.option("--vpn", type=click.Path(exists=True, dir_okay=False), default=None,
              help="Path to .ovpn file for VPN connection (CTF mode only)")
@click.option("--no-docker", is_flag=True, help="Skip Docker container (nmap/tools won't work)")
@click.option("--model", default=None, metavar="MODEL_ID",
              help="LLM model for all agents (default: claude-sonnet-4-6)")
@click.option("--log", is_flag=True, default=False,
              help="Write a plain-text activity log to work/logs/<engagement>_<timestamp>.txt")
@click.option("--goal", "-g", default="", metavar="TEXT",
              help="Mission goal or specific objectives (e.g. 'find the root flag')")
@click.option("--max-cost", type=float, default=None, metavar="USD",
              help="Stop engagement when total cost exceeds this amount (e.g. 3.00)")
def main(
    target: str,
    engagement: str,
    ctf: bool,
    vpn: str | None,
    no_docker: bool,
    model: str | None,
    log: bool,
    goal: str,
    max_cost: float | None,
) -> None:
    """KonR — AI-powered penetration testing system."""
    _check_api_key()

    if model:
        config.SONNET_MODEL = model
    if max_cost is not None:
        config.MAX_COST_USD = max_cost

    run_mode = "ctf" if ctf else "pentest"

    from konr.agents.orchestrator import Orchestrator
    from konr.agents.specialists.ad import ADAgent
    from konr.agents.specialists.network_exploit import NetworkExploitAgent
    from konr.agents.specialists.osint import OsintAgent
    from konr.agents.specialists.postexploit import PostExploitAgent
    from konr.agents.specialists.recon import ReconAgent
    from konr.agents.specialists.web import WebAgent
    from konr.container.executor import CommandExecutor
    from konr.container.manager import ContainerError, ContainerManager
    from konr.core.events import EventBus
    from konr.core.session import Session
    from konr.interface.tui import KonrApp
    from konr.storage.db import FindingsDB

    config.WORK_DIR.mkdir(parents=True, exist_ok=True)
    _clean_work_dir(config.WORK_DIR)
    db            = FindingsDB(config.WORK_DIR / "findings.db")
    engagement_id = db.create_engagement(name=engagement, target_scope=target)

    bus     = EventBus()
    session = Session(engagement_id=engagement_id, bus=bus)

    container_mgr: ContainerManager | None = None
    executor: CommandExecutor | None       = None

    if not no_docker:
        try:
            container_mgr = ContainerManager()
            container_mgr.start(
                work_dir=str(config.WORK_DIR.resolve()),
                vpn_file=vpn,
                ctf_mode=ctf,
            )
            executor = CommandExecutor(container_mgr.require_running())
        except ContainerError as exc:
            click.echo(f"[warn] Docker unavailable — {exc}", err=True)
            click.echo("[warn] Continuing without container; tool execution will fail.", err=True)

    registry = {
        "recon":           ReconAgent,
        "osint":           OsintAgent,
        "web":             WebAgent,
        "network_exploit": NetworkExploitAgent,
        "ad":              ADAgent,
        "postexploit":     PostExploitAgent,
    }

    orchestrator = Orchestrator(
        session=session,
        bus=bus,
        db=db,
        executor=executor,
        ctf_mode=ctf,
        agent_registry=registry,
    )

    async def _run_engagement() -> None:
        try:
            await session.start()
            await orchestrator.run(
                engagement_id=engagement_id,
                target_scope=target,
                mode=run_mode,
                client_name=engagement,
                objectives=goal,
            )
        except Exception as exc:
            await session.error(str(exc))

    log_path: Path | None = None
    if log:
        safe = re.sub(r"[^\w\-]", "_", engagement)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_path = config.WORK_DIR / "logs" / f"{safe}_{ts}.txt"
        log_path.parent.mkdir(parents=True, exist_ok=True)

    info: dict[str, str] = {"Target": target, "Mode": run_mode.upper()}
    if goal:
        info["Goal"] = goal
    if vpn:
        info["VPN"] = vpn
    if model:
        info["Model"] = model
    else:
        info["Models"] = "Haiku (recon/osint) · Sonnet (exploit)"
    if no_docker:
        info["Docker"] = "disabled"
    if max_cost is not None:
        info["Max cost"] = f"${max_cost:.2f}"
    if log_path:
        info["Log"] = str(log_path)

    app = KonrApp(
        session=session,
        bus=bus,
        engagement_name=f"{engagement} — {target}",
        engagement_coro=_run_engagement(),
        info=info,
        log_file=log_path,
        db=db,
    )

    try:
        app.run()
    finally:
        click.echo(click.style("Quitting...", fg="green"))
        if container_mgr is not None:
            container_mgr.stop()
            container_mgr.remove()


if __name__ == "__main__":
    main()
