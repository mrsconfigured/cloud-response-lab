"""Static safety inspection only; deliberately not labeled Terraform validation."""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PlanOnlyIaC(unittest.TestCase):
    def test_no_resource_provider_or_provisioner(self):
        source = (ROOT / 'infra/terraform/main.tf').read_text()
        for word in ('resource', 'provider', 'provisioner', 'data', 'module', 'backend'):
            self.assertIsNone(re.search(r'^\s*' + word + r'\s+["{]', source, re.M))
        self.assertNotIn(chr(2), source)
        self.assertIn('filesha256', source)
        self.assertIn('plan-only-no-deployment', source)

    def test_retained_v1_is_unpublished_and_stopped_by_default(self):
        compose = json.loads((ROOT / 'infra/compose.v1.json').read_text())
        for service in compose['services'].values():
            self.assertEqual(service['restart'], 'no')
            self.assertEqual(service.get('ports', []), [])
            self.assertEqual(service['profiles'], ['reviewed'])
        self.assertTrue(all(n['internal'] for n in compose['networks'].values()))
