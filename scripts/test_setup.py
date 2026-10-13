"""Exercise the interactive installer without Docker or elevated privileges."""
import os
import pty
import select
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class SetupTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        for name in ('setup.sh', '.env.example'):
            shutil.copy(ROOT / name, self.work / name)
        bin_dir = self.work / 'bin'
        bin_dir.mkdir()
        for name, body in {
            'docker': 'printf "%s\\n" "$*" >> "$TEST_DOCKER_LOG"\n',
            'sudo': 'exit 0\n',
            'chown': 'exit 0\n',
        }.items():
            target = bin_dir / name
            target.write_text('#!/bin/sh\n' + body)
            target.chmod(0o755)
        self.env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ['PATH'],
                        TEST_DOCKER_LOG=str(self.work / 'docker.log'))

    def run_wizard(self, answers, *args, expected=0):
        master, slave = pty.openpty()
        process = subprocess.Popen(['bash', 'setup.sh', *args], cwd=self.work,
                                   env=self.env, stdin=slave, stdout=slave, stderr=slave)
        os.close(slave)
        output = ''
        pending = list(answers)
        position = 0
        deadline = time.monotonic() + 15
        try:
            while time.monotonic() < deadline:
                if select.select([master], [], [], 0.1)[0]:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    output += chunk.decode()
                    if pending and pending[0][0] in output[position:]:
                        prompt, answer = pending.pop(0)
                        position = output.index(prompt, position) + len(prompt)
                        os.write(master, (answer + '\n').encode())
                elif process.poll() is not None:
                    break
            self.assertEqual(process.wait(timeout=2), expected, output)
            self.assertFalse(pending, output)
            return output
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            os.close(master)

    def test_install_preserve_and_reset(self):
        password = 'a memorable passphrase for testing'
        output = self.run_wizard([
            ('private network? [y/N] ', 'y'),
            ('Admin password: ', 'short'),
            ('Admin password: ', password),
            ('Repeat password: ', 'wrong'),
            ('Admin password: ', password),
            ('Repeat password: ', password),
        ])
        self.assertNotIn(password, output)
        self.assertIn('Passwords do not match', output)
        secret = self.work / 'secrets/admin_password.txt'
        self.assertEqual(secret.read_text(), password + '\n')
        self.assertEqual(secret.stat().st_mode & 0o777, 0o400)
        env = self.work / '.env'
        self.assertIn('BASTION_ALLOW_PRIVATE_UPSTREAMS=true', env.read_text())
        self.assertIn('BASTION_ADMIN_ORIGIN=\n', env.read_text())
        env.write_text(env.read_text() + '\n# preserved custom settings\n')
        before = env.read_bytes()
        self.run_wizard([])
        self.assertEqual(env.read_bytes(), before)
        self.assertEqual(secret.read_text(), password + '\n')
        output = self.run_wizard([('Admin password: ', '')], '--reset-password')
        replacement = secret.read_text().strip()
        self.assertEqual(len(replacement), 32)
        self.assertIn(replacement, output)
        self.assertEqual(env.read_bytes(), before)
        self.assertFalse(list((self.work / 'secrets').glob('.admin-password.*')))
        self.assertIn('--force-recreate --wait', (self.work / 'docker.log').read_text())

    def test_reset_requires_existing_install(self):
        self.run_wizard([], '--reset-password', expected=1)
        self.assertFalse((self.work / '.env').exists())
        self.assertFalse((self.work / 'secrets').exists())


if __name__ == '__main__':
    unittest.main()
