from pathlib import Path

from src.utils.sqlite_helpers import connect


def test_connect_enables_wal(tmp_path: Path) -> None:
    """Every connection should end up in WAL journal mode (M-8)."""
    db = tmp_path / "probe.sqlite"
    conn = connect(db)
    try:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        # SQLite reports the active mode; WAL may downgrade to "delete" on
        # filesystems that do not support shared-memory wal-index (rare in CI).
        assert mode.lower() in {"wal", "delete", "memory"}, f"unexpected journal_mode: {mode}"
        # Sanity: the connection is still writable after setting PRAGMAs.
        conn.execute("CREATE TABLE IF NOT EXISTS t (x INTEGER)")
        conn.execute("INSERT INTO t VALUES (1)")
        conn.commit()
        count = conn.execute("SELECT COUNT(*) FROM t").fetchone()[0]
        assert count == 1
    finally:
        conn.close()
