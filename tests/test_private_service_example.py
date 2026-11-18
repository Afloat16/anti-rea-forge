"""The reusable service example keeps authorization in its trusted handler."""

import importlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from releaseguard.capabilities import ReplayStore, issue_capability
from releaseguard.core import GuardError
from releaseguard.project import check_project


class PrivateServiceExampleTests(unittest.TestCase):
    def setUp(self):
        self.example = Path(__file__).resolve().parents[1] / "examples" / "private_service"
        module_name = "_releaseguard_owned_private_service_example"
        package = self.example / "service"
        spec = importlib.util.spec_from_file_location(module_name, package / "__init__.py",
                                                     submodule_search_locations=[str(package)])
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        self.entry = importlib.import_module(module_name + ".entry")

        def remove_modules():
            for name in list(sys.modules):
                if name == module_name or name.startswith(module_name + "."):
                    del sys.modules[name]

        self.addCleanup(remove_modules)
        temporary = tempfile.TemporaryDirectory(prefix="private service example ")
        self.addCleanup(temporary.cleanup)
        self.store = ReplayStore.create(Path(temporary.name).resolve() / "replay.sqlite")
        self.issuer = Ed25519PrivateKey.generate()
        self.context = dict(subject="authenticated-customer", audience="owned-quote-service",
                            product="owned-quote-app", operation="quote")
        self.request = b'{"quantity":7}'
        self.calls = []
        original = self.entry.quote

        def observed(request):
            self.calls.append(request)
            return original(request)

        self.entry.quote = observed
        self.handle = self.entry.make_quote_handler(self.issuer.public_key(), self.store)

    def invoke(self, capability, *, request=None, subject="authenticated-customer", **kwargs):
        return self.handle(authenticated_subject=subject,
                           request=self.request if request is None else request,
                           capability=capability, **kwargs)

    def test_sample_layout_passes_with_all_service_sources_declared(self):
        report = check_project(self.example / "project.json")
        self.assertTrue(report["ok"])
        self.assertEqual(report["checks"]["private_inputs_checked"], 3)
        self.assertEqual([item["path"] for item in report["files"]], ["client.mjs"])

    def test_invalid_grants_changed_request_wrong_subject_and_replay_never_run_private_logic(self):
        good = issue_capability(self.issuer, **self.context, request=self.request)
        attacker = issue_capability(Ed25519PrivateKey.generate(), **self.context, request=self.request)
        for grant, kwargs in ((None, {}), (attacker, {}),
                              (good, {"request": b'{"quantity":8}'}),
                              (good, {"subject": "another-customer"})):
            with self.subTest(case=kwargs), self.assertRaises(GuardError):
                self.invoke(grant, **kwargs)
            self.assertEqual(self.calls, [])
        self.assertEqual(self.invoke(good), {"total": 290})
        self.assertEqual(self.calls, [self.request])
        with self.assertRaises(GuardError):
            self.invoke(good)
        self.assertEqual(self.calls, [self.request])

    def test_client_cannot_choose_a_key_handler_operation_or_authorization_boolean(self):
        for field, value in (("issuer_public", self.issuer.public_key()), ("handler", lambda value: True),
                             ("operation", "admin"), ("client_authorized", True)):
            with self.subTest(field=field), self.assertRaises(TypeError):
                self.invoke(None, **{field: value})
        self.assertEqual(self.calls, [])

    def test_invalid_business_input_spends_its_valid_grant_before_private_validation(self):
        request = b'{"quantity":true}'
        grant = issue_capability(self.issuer, **self.context, request=request)
        with self.assertRaisesRegex(GuardError, "Invalid quote request"):
            self.invoke(grant, request=request)
        self.assertEqual(self.calls, [request])
        with self.assertRaises(GuardError):
            self.invoke(grant, request=request)
        self.assertEqual(self.calls, [request])


if __name__ == "__main__":
    unittest.main()
