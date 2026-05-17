#!/usr/bin/env python3
"""
n8n_bootstrap.py — SQLite-level bootstrap for SOCPilots n8n workflows.

Handles credential encryption, upsert, and workflow deployment without
requiring the n8n REST API (works on fresh installs with no user password).

Usage:
  python3 n8n_bootstrap.py --help
  python3 n8n_bootstrap.py bootstrap   # Full bootstrap (credentials + workflows)
  python3 n8n_bootstrap.py credentials # Credentials only
  python3 n8n_bootstrap.py workflows   # Workflows only
"""

import argparse
import base64
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────
SCRIPT_DIR  = Path(__file__).parent
PROJECT_DIR = SCRIPT_DIR.parent
WF_DIR      = PROJECT_DIR / "Socpilots" / "workflows"
DB_PATH     = Path("/var/lib/docker/volumes/socpilots-dev_n8n_data/_data/database.sqlite")

ASSET_WF_DIR = PROJECT_DIR / "services" / "asset-scan" / "n8n_workflows"

WORKFLOW_FILES = {
    "jXI278MucaooQW1l": WF_DIR / "SOCPilots_Main.json",
    "67z9w0HklVCA5Y5E": WF_DIR / "SOCPilots_Investigation.json",
    "BbuBpP3hOjKJmmqI": WF_DIR / "SOCPilots_Enrichment.json",
    "EA76898BAB6E5913": ASSET_WF_DIR / "coverage_gap_detection.json",
    "0C3794AF3CE037B7": ASSET_WF_DIR / "daily_asset_scan.json",
}

STATIC_ENDPOINTS = {
    "MCP Wazuh":      "http://mcp-wazuh:3001/mcp",
    "MCP thehive":    "http://thehive-mcp:8080/mcp",
    "MCP Enrichment": "http://n8n:5678/mcp/enricment",
}

# ── Crypto helpers (CryptoJS / OpenSSL AES-256-CBC) ──────────────────

def _evp_bytes_to_key(password: str, salt: bytes, key_len=32, iv_len=16):
    d, d_i = b"", b""
    while len(d) < key_len + iv_len:
        d_i = hashlib.md5(d_i + password.encode() + salt).digest()
        d += d_i
    return d[:key_len], d[key_len:key_len + iv_len]


def encrypt_n8n(plaintext: str, password: str) -> str:
    """Encrypt a string in CryptoJS AES format (same as n8n credential storage)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    salt = os.urandom(8)
    key, iv = _evp_bytes_to_key(password, salt)
    data = plaintext.encode("utf-8")
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len] * pad_len)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ciphertext = enc.update(data) + enc.finalize()
    return base64.b64encode(b"Salted__" + salt + ciphertext).decode("utf-8")


def decrypt_n8n(encrypted_b64: str, password: str) -> str:
    """Decrypt a CryptoJS AES encrypted string."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    raw = base64.b64decode(encrypted_b64)
    assert raw[:8] == b"Salted__", "Not OpenSSL/CryptoJS format"
    salt = raw[8:16]
    key, iv = _evp_bytes_to_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(raw[16:]) + dec.finalize()
    return padded[:-padded[-1]].decode("utf-8")


# ── n8n container helpers ─────────────────────────────────────────────

def get_encryption_key(container: str = "socpilots-n8n") -> str:
    """Read n8n encryption key — from volume first, then container exec."""
    # Try volume path directly (works even when container is stopped)
    volume_config = Path("/var/lib/docker/volumes/socpilots_n8n_data/_data/config")
    if volume_config.exists():
        return json.loads(volume_config.read_text())["encryptionKey"]
    # Fall back to exec (requires running container)
    result = subprocess.run(
        ["docker", "exec", container, "cat", "/home/node/.n8n/config"],
        capture_output=True, text=True, check=True
    )
    return json.loads(result.stdout)["encryptionKey"]


def get_owner(db: sqlite3.Connection):
    """Return (user_id, project_id) for the global:owner user."""
    row = db.execute(
        "SELECT id FROM user WHERE roleSlug='global:owner' LIMIT 1"
    ).fetchone()
    if not row:
        raise RuntimeError("No global:owner user found in n8n DB")
    user_id = row[0]
    proj = db.execute(
        "SELECT p.id FROM project p "
        "JOIN project_relation pr ON p.id=pr.projectId "
        "WHERE pr.userId=? AND p.type='personal' LIMIT 1",
        (user_id,)
    ).fetchone()
    if not proj:
        raise RuntimeError(f"No personal project found for user {user_id}")
    return user_id, proj[0]


# ── Credential bootstrap ──────────────────────────────────────────────

CREDENTIAL_SPECS = [
    {
        "env_var":    "OPENAI_API_KEY",
        "name":       "OpenAI account",
        "type":       "openAiApi",
        "data_fn":    lambda v: {"apiKey": v, "url": ""},
        "id_env":     "N8N_CRED_OPENAI_ID",
    },
    {
        "env_var":    "MCP_API_KEY",
        "name":       "Bearer Auth account",
        "type":       "httpBearerAuth",
        "data_fn":    lambda v: {"token": v},
        "id_env":     "N8N_CRED_BEARER_ID",
    },
]


def upsert_credential(db: sqlite3.Connection, spec: dict, enc_key: str, project_id: str) -> str:
    """
    Insert or update a credential. Returns the credential ID.
    If a credential with the same name+type already exists, updates its data.
    """
    value = os.environ.get(spec["env_var"], "").strip()
    if not value:
        raise ValueError(f"Missing env var {spec['env_var']}")

    name      = spec["name"]
    cred_type = spec["type"]
    data_json = json.dumps(spec["data_fn"](value))
    encrypted = encrypt_n8n(data_json, enc_key)

    existing = db.execute(
        "SELECT id FROM credentials_entity WHERE name=? AND type=? LIMIT 1",
        (name, cred_type)
    ).fetchone()

    if existing:
        cred_id = existing[0]
        db.execute(
            "UPDATE credentials_entity SET data=?, updatedAt=datetime('now') WHERE id=?",
            (encrypted, cred_id)
        )
        print(f"  Updated credential: {name} ({cred_id})")
    else:
        cred_id = str(uuid.uuid4())[:16].replace("-", "")  # 16-char alphanum like n8n uses
        db.execute(
            "INSERT INTO credentials_entity (id, name, type, data) VALUES (?,?,?,?)",
            (cred_id, name, cred_type, encrypted)
        )
        db.execute(
            "INSERT INTO shared_credentials (credentialsId, projectId, role) VALUES (?,?,?)",
            (cred_id, project_id, "credential:owner")
        )
        print(f"  Created credential: {name} ({cred_id})")

    return cred_id


def bootstrap_credentials(db: sqlite3.Connection, enc_key: str) -> dict:
    """Create/update all required credentials. Returns {credential_name: id}."""
    _, project_id = get_owner(db)
    cred_ids = {}
    for spec in CREDENTIAL_SPECS:
        cred_id = upsert_credential(db, spec, enc_key, project_id)
        cred_ids[spec["name"]] = cred_id
    return cred_ids


# ── Workflow bootstrap ────────────────────────────────────────────────

CREDENTIAL_NODE_MAP = {
    "OpenAI Chat Model": ("openAiApi",    "OpenAI account"),
    "GPT-4o-mini":       ("openAiApi",    "OpenAI account"),
    "MCP Wazuh":         ("httpBearerAuth", "Bearer Auth account"),
}


def patch_workflow(data: dict, cred_ids: dict) -> dict:
    """Patch credential IDs and enforce static endpoint URLs in workflow nodes."""
    for node in data.get("nodes", []):
        name = node.get("name", "")

        # Patch credential references
        if name in CREDENTIAL_NODE_MAP:
            cred_type, cred_name = CREDENTIAL_NODE_MAP[name]
            if cred_name in cred_ids:
                cred_section = {
                    "openAiApi":      "openAiApi",
                    "httpBearerAuth": "httpBearerAuth",
                }.get(cred_type, cred_type)
                node.setdefault("credentials", {})[cred_section] = {
                    "id":   cred_ids[cred_name],
                    "name": cred_name,
                }

        # Enforce static MCP endpoint URLs
        if name in STATIC_ENDPOINTS:
            node["parameters"]["endpointUrl"] = STATIC_ENDPOINTS[name]

    return data


def deploy_workflow(db: sqlite3.Connection, wf_id: str, wf_file: Path, cred_ids: dict):
    """Deploy a single workflow to n8n SQLite."""
    data = json.load(open(wf_file))
    data = patch_workflow(data, cred_ids)

    nodes_json  = json.dumps(data["nodes"])
    conns_json  = json.dumps(data["connections"])
    new_vid     = str(uuid.uuid4())
    name        = data["name"]

    existing = db.execute(
        "SELECT id FROM workflow_entity WHERE id=?", (wf_id,)
    ).fetchone()

    if existing:
        db.execute(
            "UPDATE workflow_entity SET name=?, nodes=?, connections=?, "
            "versionId=?, activeVersionId=?, active=1, updatedAt=datetime('now') "
            "WHERE id=?",
            (name, nodes_json, conns_json, new_vid, new_vid, wf_id)
        )
        print(f"  Updated workflow: {name} ({wf_id})")
    else:
        db.execute(
            "INSERT INTO workflow_entity "
            "(id, name, nodes, connections, active, versionId, activeVersionId, settings, staticData, "
            "pinData, meta, createdAt, updatedAt) "
            "VALUES (?,?,?,?,1,?,?,?,?,?,?,datetime('now'),datetime('now'))",
            (wf_id, name, nodes_json, conns_json, new_vid, new_vid,
             json.dumps({"executionOrder": "v1"}), "{}", "{}", "{}")
        )
        # Link to owner's personal project (projectId + role text — n8n v1.x schema)
        try:
            _, project_id = get_owner(db)
            db.execute(
                "INSERT OR IGNORE INTO shared_workflow (workflowId, projectId, role) VALUES (?,?,?)",
                (wf_id, project_id, "workflow:owner")
            )
        except Exception as _e:
            print(f"  WARN: could not insert shared_workflow for {wf_id}: {_e}")
        print(f"  Created workflow: {name} ({wf_id})")

    # Insert workflow_history entry so n8n treats it as "published" (not draft)
    existing_hist = db.execute(
        "SELECT 1 FROM workflow_history WHERE versionId=?", (new_vid,)
    ).fetchone()
    if not existing_hist:
        db.execute(
            "INSERT INTO workflow_history "
            "(versionId, workflowId, authors, nodes, connections, name, autosaved) "
            "VALUES (?,?,'socpilots-deploy',?,?,?,0)",
            (new_vid, wf_id, nodes_json, conns_json, name)
        )


def bootstrap_workflows(db: sqlite3.Connection, cred_ids: dict):
    """Deploy all three workflows."""
    for wf_id, wf_file in WORKFLOW_FILES.items():
        if not wf_file.exists():
            print(f"  WARNING: {wf_file} not found — skipping")
            continue
        deploy_workflow(db, wf_id, wf_file, cred_ids)


# ── API key injection ─────────────────────────────────────────────────

def inject_api_key(db: sqlite3.Connection, label: str = "socpilots-deploy") -> str:
    """Inject a raw n8n API key into the DB. Returns the raw key."""
    owner_id, _ = get_owner(db)
    raw_key = "n8n_api_" + uuid.uuid4().hex + uuid.uuid4().hex[:8]
    key_id  = str(uuid.uuid4())
    scopes  = json.dumps([
        "credential:create", "credential:delete", "credential:list",
        "credential:read",   "credential:update",
        "workflow:activate", "workflow:create", "workflow:delete",
        "workflow:list",     "workflow:read",   "workflow:update",
    ])
    db.execute("DELETE FROM user_api_keys WHERE label=? AND userId=?", (label, owner_id))
    db.execute(
        "INSERT INTO user_api_keys (id, userId, label, apiKey, scopes) VALUES (?,?,?,?,?)",
        (key_id, owner_id, label, raw_key, scopes)
    )
    return raw_key


# ── Main ──────────────────────────────────────────────────────────────

def run(mode: str, container: str):
    if not DB_PATH.exists():
        sys.exit(f"ERROR: n8n DB not found at {DB_PATH}")

    print(f"\n[bootstrap] mode={mode} db={DB_PATH}")

    enc_key = get_encryption_key(container)
    print(f"[bootstrap] Encryption key retrieved from container '{container}'")

    db = sqlite3.connect(str(DB_PATH))

    try:
        cred_ids = {}

        if mode in ("bootstrap", "credentials"):
            print("\n── Credentials ─────────────────────────────────────────────")
            cred_ids = bootstrap_credentials(db, enc_key)
            print(f"  Credential IDs: {cred_ids}")

        if mode in ("bootstrap", "workflows"):
            if not cred_ids:
                # Load existing credential IDs from DB
                for spec in CREDENTIAL_SPECS:
                    row = db.execute(
                        "SELECT id FROM credentials_entity WHERE name=? LIMIT 1",
                        (spec["name"],)
                    ).fetchone()
                    if row:
                        cred_ids[spec["name"]] = row[0]
                    else:
                        print(f"  WARNING: credential '{spec['name']}' not found — run with 'credentials' first")
            print("\n── Workflows ───────────────────────────────────────────────")
            bootstrap_workflows(db, cred_ids)

        if mode == "apikey":
            print("\n── API Key ─────────────────────────────────────────────────")
            raw_key = inject_api_key(db)
            print(f"  API key: {raw_key}")
            # Write to temp file for use by calling script
            Path("/tmp/n8n-deploy-api-key.txt").write_text(raw_key)

        db.commit()
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        db.commit()
        print("\n[bootstrap] Done — WAL checkpoint complete")

    except Exception as e:
        db.rollback()
        sys.exit(f"ERROR: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOCPilots n8n bootstrap")
    parser.add_argument("mode", choices=["bootstrap", "credentials", "workflows", "apikey"],
                        default="bootstrap", nargs="?")
    parser.add_argument("--container", default="socpilots-n8n")
    args = parser.parse_args()

    # Load .env
    env_file = PROJECT_DIR / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())

    run(args.mode, args.container)
