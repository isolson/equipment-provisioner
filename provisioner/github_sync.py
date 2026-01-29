"""GitHub repository synchronization for configs and firmware."""

import asyncio
import logging
import os
from pathlib import Path
from typing import Optional, Dict, Any

import git
import yaml

logger = logging.getLogger(__name__)


class GitHubSync:
    """Synchronizes configuration and firmware from a GitHub repository."""

    def __init__(
        self,
        repo_url: str,
        local_path: str,
        branch: str = "main",
        deploy_key: Optional[str] = None,
        sync_interval: int = 300,
    ):
        self.repo_url = repo_url
        self.local_path = Path(local_path)
        self.branch = branch
        self.deploy_key = deploy_key
        self.sync_interval = sync_interval
        self._repo: Optional[git.Repo] = None
        self._manifest: Dict[str, Any] = {}
        self._running = False

    @property
    def configs_path(self) -> Path:
        """Path to config templates."""
        return self.local_path / "configs"

    @property
    def templates_path(self) -> Path:
        """Path to config templates."""
        return self.local_path / "configs" / "templates"

    @property
    def overrides_path(self) -> Path:
        """Path to device-specific overrides."""
        return self.local_path / "configs" / "overrides"

    @property
    def firmware_path(self) -> Path:
        """Path to firmware files."""
        return self.local_path / "firmware"

    def _get_git_ssh_command(self) -> Optional[str]:
        """Get SSH command with deploy key if configured."""
        if self.deploy_key and Path(self.deploy_key).exists():
            return f"ssh -i {self.deploy_key} -o StrictHostKeyChecking=no"
        return None

    async def clone_or_pull(self, timeout: int = 30) -> bool:
        """Clone the repository or pull latest changes.

        Args:
            timeout: Maximum seconds to wait for git operation (default 30s)
        """
        try:
            return await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None, self._clone_or_pull_sync
                ),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            logger.error(f"Git sync timed out after {timeout}s")
            return False
        except Exception as e:
            logger.error(f"Failed to sync repository: {e}")
            return False

    def _clone_or_pull_sync(self) -> bool:
        """Synchronous clone or pull operation."""
        ssh_cmd = self._get_git_ssh_command()
        env = os.environ.copy()
        if ssh_cmd:
            env["GIT_SSH_COMMAND"] = ssh_cmd

        if self.local_path.exists() and (self.local_path / ".git").exists():
            # Pull existing repo
            logger.info(f"Pulling latest changes from {self.repo_url}")
            self._repo = git.Repo(self.local_path)

            with self._repo.git.custom_environment(GIT_SSH_COMMAND=ssh_cmd) if ssh_cmd else nullcontext():
                origin = self._repo.remotes.origin
                origin.pull(self.branch)

            logger.info("Repository updated successfully")
        else:
            # Clone new repo
            logger.info(f"Cloning repository {self.repo_url}")
            self.local_path.mkdir(parents=True, exist_ok=True)

            self._repo = git.Repo.clone_from(
                self.repo_url,
                self.local_path,
                branch=self.branch,
                env=env,
            )
            logger.info("Repository cloned successfully")

        # Load manifest
        self._load_manifest()
        return True

    def _load_manifest(self) -> None:
        """Load the firmware/config manifest file."""
        manifest_path = self.local_path / "manifest.yaml"
        if manifest_path.exists():
            with open(manifest_path, "r") as f:
                self._manifest = yaml.safe_load(f) or {}
            logger.info("Loaded manifest.yaml")
        else:
            logger.warning("No manifest.yaml found in repository")
            self._manifest = {}

    def get_latest_firmware_version(self, device_type: str, model: Optional[str] = None) -> Optional[str]:
        """Get the latest firmware version for a device type."""
        firmware_info = self._manifest.get("firmware", {}).get(device_type, {})

        if model and model in firmware_info:
            return firmware_info[model].get("version")
        elif "default" in firmware_info:
            return firmware_info["default"].get("version")
        elif "version" in firmware_info:
            return firmware_info["version"]

        return None

    def get_firmware_path(self, device_type: str, model: Optional[str] = None) -> Optional[Path]:
        """Get the path to the firmware file for a device type."""
        firmware_info = self._manifest.get("firmware", {}).get(device_type, {})

        if model and model in firmware_info:
            filename = firmware_info[model].get("file")
        elif "default" in firmware_info:
            filename = firmware_info["default"].get("file")
        elif "file" in firmware_info:
            filename = firmware_info["file"]
        else:
            filename = None

        if filename:
            path = self.firmware_path / device_type / filename
            if path.exists():
                return path

        # Fallback: look for firmware file in device type directory
        device_firmware_dir = self.firmware_path / device_type
        if device_firmware_dir.exists():
            files = list(device_firmware_dir.glob("*"))
            if files:
                return files[0]

        return None

    # Model aliases for config templates - maps model to config name
    # This allows different models to share the same config template
    CONFIG_MODEL_ALIASES = {
        "tachyon": {
            # TNA-303L uses the same config as TNA-303X
            "tna-303l": "tna-303x",
            "tna-303l-65": "tna-303x",
        },
        "cambium": {
            # ePMP 4518 SM default config
            "epmp 4518": "f4518-sm-defaultconfig",
        },
    }

    def get_config_template(self, device_type: str, model: Optional[str] = None) -> Optional[Path]:
        """Get the path to the config template for a device type.

        Searches in order:
        1. {templates_path}/{device_type}/{model}.json (model-specific in subdir)
        2. {templates_path}/{device_type}/{alias}.json (aliased model in subdir)
        3. {templates_path}/{device_type}/default.json (default in subdir)
        4. {templates_path}/{device_type}/*.json (any file in subdir)
        5. {templates_path}/{device_type}_{model}.json (legacy model-specific)
        6. {templates_path}/{device_type}.json (legacy device type)
        """
        device_dir = self.templates_path / device_type

        # Check for model alias (e.g., TNA-303L -> TNA-303X)
        model_alias = None
        if model and device_type in self.CONFIG_MODEL_ALIASES:
            model_key = model.lower()
            model_alias = self.CONFIG_MODEL_ALIASES[device_type].get(model_key)
            if model_alias:
                logger.debug(f"Config model alias: {model} -> {model_alias}")

        # Check device type subdirectory (new structure from web uploads)
        if device_dir.exists() and device_dir.is_dir():
            # Model-specific template in subdirectory
            if model:
                for ext in [".json", ".rsc", ".yaml", ".tar", ".tar.gz"]:
                    model_template = device_dir / f"{model}{ext}"
                    if model_template.exists():
                        return model_template

            # Try aliased model template (e.g., TNA-303L -> TNA-303X config)
            if model_alias:
                for ext in [".json", ".rsc", ".yaml", ".tar", ".tar.gz"]:
                    alias_template = device_dir / f"{model_alias}{ext}"
                    if alias_template.exists():
                        logger.info(f"Using aliased config template: {alias_template.name} for model {model}")
                        return alias_template

            # Default template in subdirectory
            for ext in [".json", ".rsc", ".yaml", ".tar", ".tar.gz"]:
                default_template = device_dir / f"default{ext}"
                if default_template.exists():
                    return default_template

            # Any config file in subdirectory (first one found)
            # Exclude ap.* files — those are AP naming templates, not provisioning configs
            for ext in [".json", ".rsc", ".yaml", ".tar", ".tar.gz"]:
                files = [f for f in device_dir.glob(f"*{ext}")
                         if not f.stem.lower().startswith("ap")]
                if files:
                    return sorted(files)[0]  # Return first alphabetically

        # Legacy: Check for model-specific template in root
        if model:
            for ext in [".json", ".rsc", ".yaml"]:
                model_template = self.templates_path / f"{device_type}_{model}{ext}"
                if model_template.exists():
                    return model_template

        # Legacy: Check aliased model template in root
        if model_alias:
            for ext in [".json", ".rsc", ".yaml"]:
                alias_template = self.templates_path / f"{device_type}_{model_alias}{ext}"
                if alias_template.exists():
                    logger.info(f"Using aliased config template: {alias_template.name} for model {model}")
                    return alias_template

        # Legacy: Fall back to device type template in root
        for ext in [".json", ".rsc", ".yaml", ".txt"]:
            template = self.templates_path / f"{device_type}{ext}"
            if template.exists():
                return template

        logger.warning(f"No config template found for {device_type}/{model}")
        return None

    def get_device_override(self, mac_address: str) -> Optional[Dict[str, Any]]:
        """Get device-specific override configuration by MAC address."""
        # Normalize MAC address format
        mac_normalized = mac_address.upper().replace(":", "-")

        override_path = self.overrides_path / f"{mac_normalized}.json"
        if override_path.exists():
            with open(override_path, "r") as f:
                return yaml.safe_load(f)

        # Also check YAML format
        override_path = self.overrides_path / f"{mac_normalized}.yaml"
        if override_path.exists():
            with open(override_path, "r") as f:
                return yaml.safe_load(f)

        return None

    async def start_periodic_sync(self) -> None:
        """Start periodic synchronization in the background."""
        self._running = True
        logger.info(f"Starting periodic sync every {self.sync_interval} seconds")

        while self._running:
            await self.clone_or_pull()
            await asyncio.sleep(self.sync_interval)

    def stop_periodic_sync(self) -> None:
        """Stop periodic synchronization."""
        self._running = False


class nullcontext:
    """Null context manager for Python < 3.7 compatibility."""
    def __enter__(self):
        return None
    def __exit__(self, *args):
        pass


# Global sync instance
_sync: Optional[GitHubSync] = None


def get_sync() -> GitHubSync:
    """Get the global GitHubSync instance."""
    if _sync is None:
        raise RuntimeError("GitHubSync not initialized. Call init_sync() first.")
    return _sync


def init_sync(
    repo_url: str,
    local_path: str,
    branch: str = "main",
    deploy_key: Optional[str] = None,
    sync_interval: int = 300,
) -> GitHubSync:
    """Initialize the global GitHubSync instance."""
    global _sync
    _sync = GitHubSync(
        repo_url=repo_url,
        local_path=local_path,
        branch=branch,
        deploy_key=deploy_key,
        sync_interval=sync_interval,
    )
    return _sync
