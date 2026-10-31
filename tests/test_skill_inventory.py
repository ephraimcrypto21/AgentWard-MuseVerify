import json
from pathlib import Path
import tempfile
import unittest

from tools.manage_cybersecurity_skills import ROOT, tree_digest


class SkillInventoryTests(unittest.TestCase):
    def test_lock_is_complete_unique_and_pinned(self):
        lock = json.loads((ROOT / 'security/skills.lock.json').read_text())
        self.assertRegex(lock['commit'], r'^[0-9a-f]{40}$')
        self.assertEqual(lock['skill_count'], len(lock['skills']))
        self.assertEqual(len({s['name'] for s in lock['skills']}), lock['skill_count'])
        for skill in lock['skills']:
            self.assertRegex(skill['name'], r'^[a-z0-9]+(?:-[a-z0-9]+)*$')
            self.assertEqual(skill['path'], 'skills/' + skill['name'])
            self.assertRegex(skill['tree_sha256'], r'^[0-9a-f]{64}$')

    def test_digest_detects_content_path_and_link_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'SKILL.md'
            path.write_text('original')
            original = tree_digest(root)
            path.write_text('tampered')
            self.assertNotEqual(tree_digest(root), original)
            path.write_text('original')
            path.rename(root / 'renamed.md')
            self.assertNotEqual(tree_digest(root), original)
            path.symlink_to(root / 'renamed.md')
            with self.assertRaises(ValueError):
                tree_digest(root)
