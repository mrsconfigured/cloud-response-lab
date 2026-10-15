import ast
import unittest
from lab import ROOT, load


class Staging(unittest.TestCase):
    def test_no_execution_capability_in_offline_engine(self):
        tree = ast.parse((ROOT / 'lab.py').read_text())
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add(node.module)
        self.assertEqual(imports, {'datetime', 'hashlib', 'json', 'pathlib'})

    def test_all_bind_mounts_refuse_missing_paths(self):
        compose = load(ROOT / 'infra/compose.staged.json')
        for service in compose['services'].values():
            for mount in service.get('volumes', []):
                if isinstance(mount, dict):
                    self.assertEqual(mount['type'], 'bind')
                    self.assertTrue(mount['read_only'])
                    self.assertFalse(mount['bind']['create_host_path'])

    def test_attack_mapping_resolves_to_rules(self):
        mapping = load(ROOT / 'attacks/mapping.json')
        self.assertEqual(mapping['status'], 'documentation-only-no-execution')
        for technique in mapping['techniques']:
            rule = load(ROOT / 'detections' / (technique['rule'] + '.json'))
            self.assertEqual(technique['event'], rule['detection']['selection']['eventName'])


if __name__ == '__main__':
    unittest.main()
