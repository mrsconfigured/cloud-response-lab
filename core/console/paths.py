"""Where the console keeps its files. Set LAB_HOME on the lab host; nothing host-specific is hard-coded in the repo."""
import os
from pathlib import Path


def home():
    return Path(os.environ.get('LAB_HOME', str(Path.home() / '.lab-console')))


def env_file():
    return home() / 'lab.env'


def state_dir():
    d = home() / 'state'
    d.mkdir(parents=True, exist_ok=True)
    return d


def ci_dir():
    d = home() / 'ci'
    d.mkdir(parents=True, exist_ok=True)
    return d


def azure_envfile():
    return home() / 'ingest' / '.azenv.tmp'
