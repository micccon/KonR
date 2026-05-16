"""Docker container lifecycle — create, start, stop, cleanup."""
from __future__ import annotations

import shutil

import docker.errors
from docker.models.containers import Container

import docker
from konr.core import config


class ContainerError(Exception):
    pass


class ContainerManager:
    def __init__(self) -> None:
        """Connect to the Docker daemon, raising ContainerError if unavailable."""
        try:
            self._client = docker.from_env()
        except docker.errors.DockerException as exc:
            raise ContainerError(f"Cannot connect to Docker daemon: {exc}") from exc

        self._container: Container | None = None
        self._stopped_container: Container | None = None  # preserved for evidence after stop()

    # ── Lifecycle ─────────────────────────────────────────────────────────

    def start(
        self,
        *,
        work_dir: str = str(config.WORK_DIR.resolve()),
        vpn_file: str | None = None,
        ctf_mode: bool = False,
        extra_hosts: dict[str, str] | None = None,
    ) -> Container:
        if self._container is not None:
            raise ContainerError("Container already running — call stop() first")

        volumes: dict[str, dict[str, str]] = {
            work_dir: {"bind": "/work", "mode": "rw"},
        }
        if ctf_mode and vpn_file:
            vpn_dest = config.VPN_DIR / "connection.ovpn"
            vpn_dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(vpn_file, vpn_dest)
            volumes[str(config.VPN_DIR.resolve())] = {"bind": "/vpn", "mode": "ro"}

        cap_add = ["NET_RAW", "NET_ADMIN"]
        devices = ["/dev/net/tun:/dev/net/tun:rwm"] if ctf_mode else []

        # Pass OSINT API keys so agents can call Shodan, Censys, Hunter, VirusTotal.
        # Only forward keys that are actually set; empty strings are omitted.
        env = {k: v for k, v in {
            "SHODAN_API_KEY":    config.SHODAN_API_KEY,
            "CENSYS_API_ID":     config.CENSYS_API_ID,
            "CENSYS_API_SECRET": config.CENSYS_API_SECRET,
            "HUNTER_API_KEY":    config.HUNTER_API_KEY,
            "VIRUSTOTAL_API_KEY": config.VIRUSTOTAL_API_KEY,
        }.items() if v}

        try:
            self._container = self._client.containers.run(
                image=config.DOCKER_IMAGE,
                command="sleep infinity",  # keep alive; executor runs cmds via exec
                detach=True,
                remove=False,  # we clean up explicitly so we can inspect on failure
                volumes=volumes,
                cap_add=cap_add,
                devices=devices if devices else None,
                extra_hosts=extra_hosts or {},
                network_mode="host",  # agents need direct network access
                working_dir="/work",
                environment=env,
            )
        except docker.errors.ImageNotFound:
            raise ContainerError(
                f"Image '{config.DOCKER_IMAGE}' not found. Run 'make docker-build' first."
            )
        except docker.errors.APIError as exc:
            raise ContainerError(f"Failed to start container: {exc}") from exc

        return self._container

    def stop(self) -> None:
        """Stop the running container. Preserves it for inspection until remove() is called."""
        if self._container is None:
            return
        try:
            self._container.stop(timeout=3)
        except docker.errors.APIError:
            pass
        finally:
            self._stopped_container = self._container
            self._container = None

    def remove(self) -> None:
        """Explicitly remove the stopped container. Call when evidence is no longer needed."""
        target = self._stopped_container or self._container
        if target is None:
            return
        try:
            target.remove(force=True)
        except docker.errors.APIError:
            pass
        finally:
            self._stopped_container = None
            self._container = None

    # ── Status ────────────────────────────────────────────────────────────

    @property
    def is_running(self) -> bool:
        """Check Docker daemon for live container status (reloads from daemon each call)."""
        if self._container is None:
            return False
        try:
            self._container.reload()
            return self._container.status == "running"
        except docker.errors.APIError:
            return False

    @property
    def container_id(self) -> str | None:
        """Short container ID for display, or None if no container is active."""
        return self._container.short_id if self._container else None

    def require_running(self) -> Container:
        """Return the running container or raise ContainerError if it's not up."""
        if not self.is_running:
            raise ContainerError("No container running")
        assert self._container is not None
        return self._container

    # ── Context manager ───────────────────────────────────────────────────

    def __enter__(self) -> ContainerManager:
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()
        self.remove()
