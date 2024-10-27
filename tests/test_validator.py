import unittest
from app.validator import Email


class TestEmail(unittest.TestCase):
    def test_verify_valid_email(self):
        email = Email("cansinacarer@gmail.com")
        result = email.verify()
        self.assertIsInstance(result, dict)
        self.assertEqual(result.get("email"), "cansinacarer@gmail.com")
        self.assertTrue(result.get("is_free_provider"))
        self.assertEqual(result.get("smtp_provider_host_domain"), "google")
        self.assertEqual(result.get("status"), "valid")
        self.assertEqual(
            result.get("status_detail"),
            "email provider confirmed that the email address is deliverable",
        )

    def test_verify_valid_alias_email(self):
        email = Email("cansinacarer+test@gmail.com")
        result = email.verify()
        self.assertIsInstance(result, dict)
        self.assertTrue(result.get("is_alias"))

    def test_verify_role_email(self):
        email = Email("info@cansin.net")
        result = email.verify()
        self.assertIsInstance(result, dict)
        self.assertTrue(result.get("is_role"))

    def test_verify_catchall(self):
        email = Email("info@cansin.net")
        result = email.verify()
        self.assertIsInstance(result, dict)
        self.assertTrue(result.get("is_catch_all"))
        self.assertTrue(result.get("is_role"))

    def test_verify_disposable(self):
        email = Email("xcgn@gimpmail.com")
        result = email.verify()
        self.assertIsInstance(result, dict)
        self.assertTrue(result.get("is_disposable"))

    def test_verify_invalid_address(self):
        email = Email("test23gf43w5f@cacarer.com")
        result = email.verify()
        self.assertIsInstance(result, dict)
        self.assertEqual(result.get("status"), "invalid")
        self.assertEqual(
            result.get("status_detail"),
            "email provider confirmed that email address does not exist",
        )

    def test_verify_invalid_domain(self):
        email = Email("test@cansin.net.com")
        result = email.verify()
        self.assertIsInstance(result, dict)
        self.assertEqual(result.get("status"), "invalid")
        self.assertEqual(
            result.get("status_detail"), "email domain does not have emails set up"
        )


if __name__ == "__main__":
    unittest.main()
