"""Deployment safety tests; no root, systemd, DNS, or certificate changes."""
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / 'deploy' / 'olamidepanel.py'
spec = importlib.util.spec_from_file_location('nearmarket_deployer', MODULE)
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.cfg = {'domain': 'market.example.com', 'email': 'owner@example.com',
                    'expected_ipv4': '192.0.2.10', 'port': 18361, 'commit': 'a' * 40}

    def test_policy_rejects_injection_and_invalid_ports(self):
        d.validate(self.cfg)
        for invalid in ({'domain': 'market.example.com;evil'}, {'domain': '../etc/passwd'},
                        {'port': 80}, {'port': 70000}, {'expected_ipv4': '::1'},
                        {'commit': '--upload-pack=bad'}):
            with self.subTest(invalid=invalid), self.assertRaises(d.DeploymentError):
                d.validate({**self.cfg, **invalid})

    def test_dns_blocks_wrong_ip_and_ipv6_before_mutation(self):
        def answers(argv, **kwargs):
            if argv[-1] == 'AAAA':
                return ''
            return 'market.example.com. 60 IN A 192.0.2.10\n'
        with patch.object(d, 'run', side_effect=answers):
            self.assertEqual(len(d.check_dns(self.cfg['domain'], '192.0.2.10')), 2)
            with self.assertRaises(d.DeploymentError):
                d.check_dns(self.cfg['domain'], '192.0.2.11')
        with patch.object(d, 'run', return_value='market.example.com. 60 IN AAAA 2001:db8::1\n'):
            with self.assertRaises(d.DeploymentError):
                d.check_dns(self.cfg['domain'], '192.0.2.10')

    def test_port_conflict_never_stops_other_service(self):
        with patch.object(d, 'run', return_value='LISTEN 0 100 0.0.0.0:18361 0.0.0.0:* users:(("other",pid=55,fd=3))\n') as run:
            with self.assertRaises(d.DeploymentError):
                d.check_port(18361)
            self.assertEqual(run.call_count, 1)
        with patch.object(d, 'run', return_value=''):
            d.check_port(18361)

    def test_generated_configuration_is_private_and_tls_first(self):
        unit = d.unit_text()
        self.assertIn('User=nearmarket', unit)
        self.assertIn('ProtectSystem=strict', unit)
        self.assertIn('LoadCredential=nearmarket_gateway_key:/etc/nearmarket/gateway.key', unit)
        self.assertIn('ReadWritePaths=/var/lib/nearmarket', unit)
        self.assertIn('HOST=127.0.0.1', d.environment(self.cfg))
        bootstrap = d.nginx_text(self.cfg, False)
        self.assertNotIn('proxy_pass', bootstrap)
        self.assertIn('return 503', bootstrap)
        tls = d.nginx_text(self.cfg, True)
        self.assertIn('proxy_pass http://127.0.0.1:18361', tls)
        self.assertIn('limit_req', tls)
        self.assertIn('listen 443 ssl', tls)
        self.assertNotIn('default_server', tls)
        self.assertNotIn('ssl_verify off', tls)

    def test_atomic_write_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / 'target'
            target.write_text('unchanged')
            link = Path(root) / 'link'
            link.symlink_to(target)
            with self.assertRaises(d.DeploymentError):
                d.atomic(link, 'bad')
            self.assertEqual(target.read_text(), 'unchanged')

    def test_archive_rejects_symlinks_and_keeps_files_readable(self):
        with tempfile.TemporaryDirectory() as root, patch.object(d, 'BASE', Path(root)):
            (Path(root) / 'releases').mkdir()
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w') as archive:
                for name in ('app.py', 'tenants.py', 'payments.py', 'static/index.html'):
                    data = b'fixture\n'
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            old_umask = os.umask(0o077)
            try:
                with patch.object(d, 'run', return_value=stream.getvalue()):
                    release = d.export_release('unused', 'a' * 40)
                    self.assertEqual((release / 'static').stat().st_mode & 0o777, 0o755)
                    self.assertEqual((release / 'REVISION').stat().st_mode & 0o777, 0o644)
            finally:
                os.umask(old_umask)
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w') as archive:
                info = tarfile.TarInfo('escape')
                info.type = tarfile.SYMTYPE
                info.linkname = '/etc/passwd'
                archive.addfile(info)
            with patch.object(d, 'run', return_value=stream.getvalue()), self.assertRaises(d.DeploymentError):
                d.export_release('unused', 'b' * 40)

    def test_nginx_conflict_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / 'nearmarket.conf'
            link = Path(root) / 'enabled' / 'nearmarket.conf'
            link.parent.mkdir()
            dump = '# configuration file /another/site.conf:\nserver { server_name market.example.com; }\n'
            with patch.object(Path, 'is_dir', return_value=True), self.assertRaises(d.DeploymentError):
                d.check_nginx('market.example.com', target, link, dump)
            # Explicit hostnames can coexist with a panel wildcard.
            with patch.object(Path, 'is_dir', return_value=True):
                d.check_nginx('market.example.com', target, link, dump.replace('market.example.com', '*.example.com'))

    def test_identity_check_cannot_accept_another_application(self):
        with patch.object(d, 'run', return_value=json.dumps({'status': 'ok', 'application': 'other', 'release': 'a' * 40})), self.assertRaises(d.DeploymentError):
            d.health(self.cfg)

    def test_failed_candidate_restores_release_and_configuration_without_deleting_data(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            base = root / 'app'
            old = base / 'releases' / ('b' * 40)
            new = base / 'releases' / ('a' * 40)
            for directory in (old, new, base / 'source', root / 'backups', root / 'data', root / 'available', root / 'enabled', root / 'etc'):
                directory.mkdir(parents=True, exist_ok=True)
            (base / 'current').symlink_to(old)
            unit = root / 'etc' / 'nearmarket.service'
            env = root / 'etc' / 'runtime.env'
            unit.write_text(d.MARK + 'previous service')
            env.write_text('PREVIOUS_RUNTIME=1\n')
            target = root / 'available' / ('nearmarket-' + self.cfg['domain'] + '.conf')
            target.write_text(d.MARK + 'previous nginx')
            (root / 'enabled' / target.name).symlink_to(target)
            database = root / 'data' / 'market.db'
            with sqlite3.connect(database) as c:
                c.execute('CREATE TABLE important(value TEXT)')
                c.execute("INSERT INTO important VALUES('retain this')")
            cfg = {**self.cfg, 'run_tests': False, 'publish_panel_inventory': False}
            report = {'changed': False}
            def fake_run(argv, **kwargs):
                return cfg['commit'] if argv[0] == 'git' else ''
            with patch.multiple(d, BASE=base, BACKUPS=root / 'backups', DATA=root / 'data', UNIT=unit, ENV=env,
                                NGINX_AVAILABLE=root / 'available', NGINX_ENABLED=root / 'enabled'), \
                 patch.object(d, 'active', return_value=True), \
                 patch.object(d, 'run', side_effect=fake_run) as commands, \
                 patch.object(d, 'check_nginx'), patch.object(d, 'check_port'), \
                 patch.object(d, 'check_dns', return_value=[]), \
                 patch.object(d, 'export_release', return_value=new), \
                 patch.object(d, 'health', side_effect=d.DeploymentError('fixture failure')), \
                 patch.object(d.time, 'sleep'), \
                 patch.object(d.subprocess, 'run', return_value=SimpleNamespace(returncode=0)):
                with self.assertRaises(d.DeploymentError):
                    d.deploy(cfg, report)
            self.assertEqual((base / 'current').resolve(), old)
            self.assertEqual(env.read_text(), 'PREVIOUS_RUNTIME=1\n')
            self.assertEqual(unit.read_text(), d.MARK + 'previous service')
            self.assertEqual(target.read_text(), d.MARK + 'previous nginx')
            self.assertEqual(report['rollback'], 'configuration_restored_data_retained')
            with sqlite3.connect(database) as c:
                self.assertEqual(c.execute('SELECT value FROM important').fetchone()[0], 'retain this')
            self.assertTrue((Path(report['backup']) / 'market.db').exists())
            self.assertFalse(any(call.args[0][:3] == ['systemctl', 'stop', 'nginx.service'] for call in commands.call_args_list))

    def test_acme_probe_waits_for_new_nginx_workers(self):
        calls = {'body': 0}
        def response(argv, **kwargs):
            if '--write-out' in argv:
                return '503'
            calls['body'] += 1
            if calls['body'] <= 2:
                raise d.DeploymentError('old worker response')
            return 'NearMarket-ACME'
        report = {}
        with patch.object(d, 'run', side_effect=response), patch.object(d.time, 'sleep') as pause:
            d.probe_acme(self.cfg, Path('probe-fixture'), report, attempts=3)
        self.assertEqual(calls['body'], 3)
        self.assertEqual(report['acme_verified_address'], self.cfg['expected_ipv4'])
        pause.assert_called_once_with(1)

    def test_acme_probe_can_use_loopback_if_public_hairpin_is_unavailable(self):
        def response(argv, **kwargs):
            if self.cfg['domain'] + ':80:127.0.0.1' in argv:
                return 'NearMarket-ACME'
            raise d.DeploymentError('unreachable fixture')
        report = {}
        with patch.object(d, 'run', side_effect=response):
            d.probe_acme(self.cfg, Path('probe-fixture'), report, attempts=1)
        self.assertEqual(report['acme_verified_address'], '127.0.0.1')

    def test_acme_failure_reports_codes_without_response_bodies(self):
        def response(argv, **kwargs):
            if '--write-out' in argv:
                return '403'
            raise d.DeploymentError('fixture')
        report = {}
        with patch.object(d, 'run', side_effect=response), self.assertRaises(d.DeploymentError) as error:
            d.probe_acme(self.cfg, Path('probe-fixture'), report, attempts=1)
        self.assertIn('127.0.0.1=403', str(error.exception))
        self.assertEqual(len(report['acme_probe']), 2)
        self.assertEqual(report['acme_probe'][0]['http_status'], '403')

    def test_listeners_join_only_existing_address_groups(self):
        dump = 'server { listen 127.0.0.1:80; listen 192.0.2.10:443 ssl; listen 192.0.2.55:80; }'
        policy = d.listener_policy(self.cfg, dump)
        self.assertEqual(policy, {'80': ['127.0.0.1'], '443': ['192.0.2.10']})
        text = d.nginx_text({**self.cfg, 'nginx_addresses': policy}, True)
        self.assertIn('listen 127.0.0.1:80;', text)
        self.assertIn('listen 192.0.2.10:443 ssl;', text)
        self.assertNotIn('listen 192.0.2.10:80;', text)
        self.assertNotIn('192.0.2.55', text)
        with self.assertRaises(d.DeploymentError):
            d.listener_policy(self.cfg, 'listen 127.0.0.1:80 proxy_protocol;')


if __name__ == '__main__':
    unittest.main()
