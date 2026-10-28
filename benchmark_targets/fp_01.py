#!/usr/bin/env python3
"""FP-01: hardcoded credentials, but only inside a mocked test double."""


class FakeSecretsBackend:
    """Stands in for Vault during unit tests.

    A linter flags the literal values below as "hardcoded credentials";
    they are intentionally fake and never used in production.
    """

    def __init__(self):
        self._store = {
            "db_user": "test_user",
            "db_password": "test_password_123",
            "api_key": "sk-test-0000000000000000",
        }

    def get(self, name):
        return self._store.get(name)


def build_connection_string(backend):
    return "postgres://{user}:{pw}@localhost:5432/testdb".format(
        user=backend.get("db_user"), pw=backend.get("db_password")
    )


def test_connection_string():
    conn = build_connection_string(FakeSecretsBackend())
    assert conn.startswith("postgres://test_user:")
    assert "@localhost" in conn


if __name__ == "__main__":
    test_connection_string()
    print("ok")
