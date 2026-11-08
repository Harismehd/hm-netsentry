from __future__ import annotations

import tempfile
from pathlib import Path
import unittest

from app.discovery.interfaces import discover_network_interfaces
from app.llm.ollama import OllamaStatus
from app.storage.database import initialize_database, table_names


class Phase1Tests(unittest.TestCase):
    def test_database_initializes(self) -> None:
        tmp_dir = Path(tempfile.mkdtemp())
        db_path = tmp_dir / "test.sqlite3"
        try:
            initialize_database(db_path)
            tables = set(table_names(db_path))
            self.assertTrue(
                {
                    "alerts",
                    "devices",
                    "dns_events",
                    "flows",
                    "investigations",
                    "network_interfaces",
                    "network_snapshots",
                    "services",
                }
                <= tables
            )
        finally:
            pass

    def test_interface_discovery_returns_list(self) -> None:
        interfaces = discover_network_interfaces()
        self.assertIsInstance(interfaces, list)
        self.assertTrue(interfaces)

    def test_ollama_status_dataclass(self) -> None:
        status = OllamaStatus(False, False, "x")
        self.assertFalse(status.reachable)


if __name__ == "__main__":
    unittest.main()
