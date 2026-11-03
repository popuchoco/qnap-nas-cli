import copy
import unittest

from qnap_nas_cli.errors import QtsError
from qnap_nas_cli.remediation import apply_plan, create_plan, unavailable_plan, validate_plan


class FakeHandler:
    def __init__(self, state):
        self.state = state
        self.applied = 0

    def read(self, operation, context):
        return dict(self.state)

    def apply(self, operation, context):
        self.applied += 1
        self.state = dict(operation["after"])
        return {"ok": True}

    def verify(self, operation, observed, context):
        return observed == operation["after"]


class RemediationTest(unittest.TestCase):
    device = {"origin": "https://nas.example", "model": "TS-431K", "firmware": "QTS 5.2"}

    def test_unavailable_action_is_bound_and_fail_closed(self):
        plan = unavailable_plan(self.device, "raid-rebuild")
        validate_plan(plan)
        self.assertEqual(plan["status"], "refused")
        self.assertEqual(plan["operations"], [])
        self.assertTrue(plan["manual_steps"])
        result = apply_plan(plan, plan["plan_id"], handlers={})
        self.assertEqual(result["status"], "refused")

    def test_plan_tampering_is_rejected(self):
        plan = unavailable_plan(self.device, "service-stop")
        edited = copy.deepcopy(plan)
        edited["manual_steps"].append("unexpected action")
        with self.assertRaises(QtsError):
            validate_plan(edited)

    def test_apply_rechecks_state_and_verifies_readback(self):
        before = {"state": "stopped"}
        after = {"state": "running"}
        handler = FakeHandler(before)
        plan = create_plan(self.device, "service-start", [{"operation": "service_start", "before": before, "after": after}])
        result = apply_plan(
            plan, plan["plan_id"], {"service_start": handler}, context="ctx",
            device_reader=lambda context: self.device,
            precondition_checker=lambda candidate, context: True,
        )
        self.assertEqual(result["status"], "applied_and_verified")
        self.assertEqual(handler.applied, 1)

    def test_apply_stops_when_state_changed_since_plan(self):
        handler = FakeHandler({"state": "running"})
        plan = create_plan(self.device, "service-start", [{"operation": "service_start", "before": {"state": "stopped"}, "after": {"state": "running"}}])
        result = apply_plan(
            plan, plan["plan_id"], {"service_start": handler},
            device_reader=lambda context: self.device,
            precondition_checker=lambda candidate, context: True,
        )
        self.assertEqual(result["status"], "stale_plan")
        self.assertEqual(handler.applied, 0)

    def test_apply_halts_after_failed_readback(self):
        class BadVerify(FakeHandler):
            def verify(self, operation, observed, context):
                return False
        first = BadVerify({"state": "stopped"})
        second = FakeHandler({"state": "stopped"})
        operations = [
            {"operation": "first", "before": {"state": "stopped"}, "after": {"state": "running"}},
            {"operation": "second", "before": {"state": "stopped"}, "after": {"state": "running"}},
        ]
        plan = create_plan(self.device, "two-step", operations)
        result = apply_plan(
            plan, plan["plan_id"], {"first": first, "second": second},
            device_reader=lambda context: self.device,
            precondition_checker=lambda candidate, context: True,
        )
        self.assertEqual(result["status"], "partial_failure")
        self.assertEqual(first.applied, 1)
        self.assertEqual(second.applied, 0)

    def test_apply_requires_explicit_confirmation_device_and_preconditions(self):
        plan = create_plan(self.device, "service-stop", [{"operation": "service_stop", "before": {"state": "running"}, "after": {"state": "stopped"}}])
        with self.assertRaises(QtsError):
            apply_plan(plan, "wrong", {"service_stop": FakeHandler({"state": "running"})})
        no_identity = apply_plan(plan, plan["plan_id"], {"service_stop": FakeHandler({"state": "running"})})
        self.assertEqual(no_identity["reason"], "no_device_identity_verifier")
        no_preconditions = apply_plan(plan, plan["plan_id"], {"service_stop": FakeHandler({"state": "running"})}, device_reader=lambda ctx: self.device)
        self.assertEqual(no_preconditions["reason"], "preconditions_not_verified")


if __name__ == "__main__":
    unittest.main()
