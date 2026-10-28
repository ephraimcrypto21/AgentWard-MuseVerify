"""False Positive 04: Mock test credentials in a unit test fixture class."""


class MockAuthTestFixture:
    TEST_USERNAME = "test_user"
    TEST_PASSWORD = "test_password_placeholder_not_real"

    def get_mock_headers(self) -> dict:
        return {"X-Test-User": self.TEST_USERNAME}
