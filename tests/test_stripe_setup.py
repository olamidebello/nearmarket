import importlib.util
from pathlib import Path
import tempfile
import unittest
spec = importlib.util.spec_from_file_location('stripe_setup',Path(__file__).resolve().parents[1]/'scripts'/'configure-stripe.py')
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)

class StripeSetup(unittest.TestCase):
    def test_preserves_other_tenants_and_updates_selected_values(self):
        text = '# local settings\nUNRELATED=value\nNEARMARKET_T2_STRIPE_SECRET=obsolete\nNEARMARKET_T1_STRIPE_SECRET=unchanged\n'
        output = setup.render(text,2,'sk_test_fixture123456','whsec_fixture123456')
        self.assertIn('UNRELATED=value',output)
        self.assertIn('NEARMARKET_T1_STRIPE_SECRET=unchanged',output)
        self.assertNotIn('obsolete',output)
        self.assertEqual(output.count('NEARMARKET_T2_STRIPE_SECRET='),1)
        self.assertNotIn('NEARMARKET_ALLOW_LIVE_PAYMENTS',output)
    def test_live_keys_require_explicit_flag_and_newlines_rejected(self):
        with self.assertRaises(ValueError):setup.render('',1,'sk_live_fixture123456','whsec_fixture123456')
        output = setup.render('',1,'sk_live_fixture123456','whsec_fixture123456',True)
        self.assertIn('NEARMARKET_ALLOW_LIVE_PAYMENTS=1',output)
        with self.assertRaises(ValueError):setup.render('',1,'sk_test_fixture\nINJECT=1','whsec_fixture123456')
    def test_file_is_private_and_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'secrets.env'
            setup.save(path,'fixture=value\n')
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            link=Path(root)/'link';link.symlink_to(path)
            with self.assertRaises(ValueError):setup.save(link,'bad')
