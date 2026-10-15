"""Conservative local structural/style checks, not external schema certification."""
import ast
import json
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Pre-existing partner files are preserved byte-for-byte and are outside this style check.
PARTNER_FILES = {'COMMAND_LOG.md', 'hello_lab.py', 'test_discord.py'}
sys.path.insert(0, str(ROOT))
from lab import load, validate_playbook, validate_rule  # noqa: E402


def require(value, message):
    if not value:
        raise ValueError(message)


def main():
    count = 0
    for path in ROOT.rglob('*'):
        if any(part in path.parts for part in ('.git', '.venv', '__pycache__', 'secrets', 'artifacts')) or not path.is_file():
            continue
        if path.relative_to(ROOT).as_posix() in PARTNER_FILES:
            continue
        if path.suffix in ('.json', '.py', '.md', '.yml'):
            text = path.read_text()
            require(text.endswith('\n'), str(path) + ': missing newline')
            require(not any(line.rstrip() != line for line in text.splitlines()), str(path) + ': trailing whitespace')
            if path.suffix == '.json':
                json.loads(text)
            if path.suffix == '.py':
                ast.parse(text)
            count += 1
    ids = set()
    for path in (ROOT / 'detections').glob('*.json'):
        rule = load(path)
        validate_rule(rule)
        uuid.UUID(rule['id'])
        require(rule['id'] not in ids, 'duplicate rule ID')
        ids.add(rule['id'])
    for path in (ROOT / 'response/playbooks').glob('*.json'):
        book = load(path)
        validate_playbook(book)
        require(book['rule_id'] in ids, 'orphan playbook')
    compose = load(ROOT / 'infra/compose.staged.json')
    for name, service in compose['services'].items():
        require(service.get('profiles') == ['reviewed'], 'unguarded profile')
        require(service.get('restart') == 'no', 'automatic restart')
        require('mem_limit' in service, 'missing memory cap')
        require(not service.get('privileged'), 'privileged container')
        require(not any('docker.sock' in str(v) for v in service.get('volumes', [])), 'docker socket forbidden')
        require(not service['image'].endswith(':latest'), 'mutable latest forbidden')
        for port in service.get('ports', []):
            require(port.startswith('127.0.0.1:'), 'non-loopback port')
    require(all(n.get('internal') for n in compose['networks'].values()), 'external container routing')
    from scripts.integration_validate import main as validate_integrations
    validate_integrations()
    print(f'PASS: {count} source files; 3 rules/playbooks; staging safety invariants')


if __name__ == '__main__':
    main()
