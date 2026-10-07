import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = (
    ROOT
    / "control-plane"
    / "supabase"
    / "migrations"
    / "20261007201000_artifact_authority_v1.sql"
)
REGISTRY = ROOT / "control-plane" / "supabase" / "migration-registry.json"


class ArtifactPostgresAuthorityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sql = MIGRATION.read_text(encoding="utf-8")
        cls.lowered = cls.sql.lower()
        cls.registry = json.loads(REGISTRY.read_text(encoding="utf-8"))

    def test_artifact_authority_is_private_metadata_not_d1_schema_copy(self) -> None:
        self.assertIn("private.ordax_artifact_records", self.lowered)
        self.assertIn("private.ordax_artifact_upload_sessions", self.lowered)
        self.assertNotIn("create table public.ordax_artifacts", self.lowered)
        self.assertNotIn("create table public.ordax_artifact_uploads", self.lowered)
        self.assertNotIn("d1", self.lowered)
        self.assertIn("producer_kind", self.lowered)
        self.assertIn("object_key", self.lowered)

    def test_r2_bytes_and_postgres_metadata_contract_is_explicit(self) -> None:
        self.assertIn("r2 owns object bytes", self.lowered)
        self.assertIn("postgresql owns durable metadata", self.lowered)
        self.assertIn("read_token_sha256", self.lowered)
        self.assertIn("r2_upload_id", self.lowered)

    def test_private_tables_are_fail_closed(self) -> None:
        for table in (
            "private.ordax_artifact_records",
            "private.ordax_artifact_upload_sessions",
        ):
            self.assertIn(f"alter table {table} enable row level security", self.lowered)
            self.assertIn(f"revoke all on table {table}", self.lowered)
        self.assertIn("artifact authority leaked direct table privileges", self.lowered)

    def test_edge_authority_is_rpc_only(self) -> None:
        expected = (
            "ordax_artifact_lookup_v1",
            "ordax_rotate_artifact_read_token_v1",
            "ordax_publish_artifact_v1",
            "ordax_get_artifact_upload_v1",
            "ordax_create_artifact_upload_v1",
            "ordax_delete_artifact_upload_v1",
            "ordax_authorize_artifact_download_v1",
            "ordax_list_artifact_device_objects_v1",
            "ordax_delete_artifact_record_v1",
            "ordax_list_artifact_retention_candidates_v1",
        )
        for rpc in expected:
            self.assertIn(f"public.{rpc}", self.lowered)
        self.assertIn("to ordax_edge_executor", self.lowered)
        self.assertIn("from public, anon, authenticated, service_role, ordax_edge_executor", self.lowered)
        self.assertIn("artifact authority rpc leaked outside edge executor", self.lowered)

    def test_object_key_is_bound_to_device_job_and_artifact(self) -> None:
        self.assertIn(
            "p_device_id::text || '/' || p_job_id::text || '/' || p_artifact_id::text || '-'",
            self.sql,
        )
        self.assertIn(
            "left(p_storage_path, char_length(v_prefix)) <> v_prefix",
            self.lowered,
        )

    def test_read_tokens_are_hash_only_and_bounded(self) -> None:
        self.assertIn("p_read_token_sha256 !~ '^[0-9a-f]{64}$'", self.lowered)
        self.assertIn("p_read_expires_at > v_now + interval '24 hours'", self.lowered)
        self.assertNotIn("read_token text", self.lowered)

    def test_registry_has_single_artifact_authority_entry(self) -> None:
        entries = [
            item
            for item in self.registry["migrations"]
            if item["name"] == "20261007201000_artifact_authority_v1"
        ]
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(
            entry["source"]["repository"],
            "ordaxsystems/ordax-control-plane",
        )
        self.assertEqual(
            entry["source"]["path"],
            "control-plane/supabase/migrations/20261007201000_artifact_authority_v1.sql",
        )
        self.assertEqual(
            entry["source"]["blob_sha"],
            "3bd6df1fe236df8860e48383a33fd9482ed0d35c",
        )


if __name__ == "__main__":
    unittest.main()
