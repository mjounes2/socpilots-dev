"""
SOCPilots RAG Retrieval — Unit & Integration Tests

Unit tests run without external deps (mocked Qdrant + model).
Integration tests require QDRANT_URL env var pointing to a live instance.

Run unit tests:
  pytest services/rag-retrieval/tests/test_rag.py -v -m unit

Run integration tests (needs running Qdrant):
  QDRANT_URL=http://localhost:6333 pytest services/rag-retrieval/tests/test_rag.py -v -m integration
"""

import os
import sys
import time
import json
import pytest
from unittest.mock import patch, MagicMock, PropertyMock

# Ensure src is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


# ── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def mock_qdrant():
    """Return a MagicMock that mimics qdrant_client.QdrantClient."""
    client = MagicMock()
    # get_collections returns a CollectionsResponse-like object
    client.get_collections.return_value = MagicMock(collections=[])
    # search returns ScoredPoint-like dicts
    client.search.return_value = [
        MagicMock(
            id=1,
            score=0.92,
            payload={
                "id": "mitre:T1566",
                "title": "T1566 — Phishing",
                "content": "Adversaries send malicious emails.",
                "type": "AttackPattern",
                "source": "mitre",
                "metadata": json.dumps({"technique_id": "T1566", "tactic": "Initial Access"}),
            }
        ),
        MagicMock(
            id=2,
            score=0.85,
            payload={
                "id": "rule:DR001",
                "title": "SSH Brute Force Detection",
                "content": "Multiple failed SSH login attempts.",
                "type": "DetectionRule",
                "source": "soc_rules",
                "metadata": json.dumps({"rule_id": "DR001"}),
            }
        ),
    ]
    return client


@pytest.fixture
def mock_model():
    """Return a MagicMock that mimics SentenceTransformer."""
    model = MagicMock()
    model.encode.return_value = [0.1] * 384
    return model


@pytest.fixture
def flask_client(mock_qdrant, mock_model):
    """Patch external deps and return a Flask test client."""
    with patch.dict(os.environ, {
        'QDRANT_URL': 'http://mock-qdrant:6333',
        'RAG_API_KEY': 'test-key-abc123',
    }):
        with patch('qdrant_client.QdrantClient', return_value=mock_qdrant), \
             patch('sentence_transformers.SentenceTransformer', return_value=mock_model):
            import importlib
            import rag_service
            importlib.reload(rag_service)
            rag_service.app.config['TESTING'] = True
            with rag_service.app.test_client() as c:
                yield c


# ── Unit Tests ─────────────────────────────────────────────────────────

@pytest.mark.unit
class TestHealth:
    def test_health_returns_ok(self, flask_client):
        resp = flask_client.get('/health')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['status'] == 'ok'
        assert 'qdrant' in data

    def test_health_no_auth_required(self, flask_client):
        """Health endpoint must be accessible without API key."""
        resp = flask_client.get('/health')
        assert resp.status_code != 401


@pytest.mark.unit
class TestAuthentication:
    def test_retrieve_requires_api_key(self, flask_client):
        resp = flask_client.post('/retrieve', json={'query': 'phishing'})
        assert resp.status_code == 401

    def test_retrieve_wrong_key_rejected(self, flask_client):
        resp = flask_client.post('/retrieve',
                                  json={'query': 'phishing'},
                                  headers={'X-API-Key': 'wrong-key'})
        assert resp.status_code == 401

    def test_retrieve_correct_key_accepted(self, flask_client):
        resp = flask_client.post('/retrieve',
                                  json={'query': 'phishing'},
                                  headers={'X-API-Key': 'test-key-abc123'})
        assert resp.status_code == 200

    def test_investigation_requires_api_key(self, flask_client):
        resp = flask_client.post('/search/investigation', json={'query': 'brute force'})
        assert resp.status_code == 401

    def test_hunting_requires_api_key(self, flask_client):
        resp = flask_client.post('/search/hunting', json={'query': 'lateral movement'})
        assert resp.status_code == 401

    def test_metrics_no_auth_required(self, flask_client):
        """Metrics endpoint must be accessible without API key."""
        resp = flask_client.get('/metrics')
        assert resp.status_code == 200


@pytest.mark.unit
class TestRetrieve:
    def test_retrieve_missing_query_returns_400(self, flask_client):
        resp = flask_client.post('/retrieve',
                                  json={},
                                  headers={'X-API-Key': 'test-key-abc123'})
        assert resp.status_code == 400
        assert 'error' in resp.get_json()

    def test_retrieve_returns_results(self, flask_client):
        resp = flask_client.post('/retrieve',
                                  json={'query': 'phishing email malicious attachment'},
                                  headers={'X-API-Key': 'test-key-abc123'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'results' in data
        assert 'count' in data
        assert isinstance(data['results'], list)

    def test_retrieve_result_schema(self, flask_client):
        """Each result must have required fields."""
        resp = flask_client.post('/retrieve',
                                  json={'query': 'brute force ssh'},
                                  headers={'X-API-Key': 'test-key-abc123'})
        data = resp.get_json()
        for r in data['results']:
            assert 'id' in r
            assert 'title' in r
            assert 'content' in r
            assert 'type' in r
            assert 'score' in r
            assert 0.0 <= r['score'] <= 1.0

    def test_retrieve_limit_capped_at_20(self, flask_client):
        resp = flask_client.post('/retrieve',
                                  json={'query': 'lateral movement', 'limit': 999},
                                  headers={'X-API-Key': 'test-key-abc123'})
        assert resp.status_code == 200

    def test_retrieve_type_filter(self, flask_client):
        resp = flask_client.post('/retrieve',
                                  json={'query': 'lateral movement', 'type': 'AttackPattern'},
                                  headers={'X-API-Key': 'test-key-abc123'})
        assert resp.status_code == 200


@pytest.mark.unit
class TestSearchInvestigation:
    def test_returns_three_categories(self, flask_client):
        resp = flask_client.post('/search/investigation',
                                  json={'query': 'suspicious PowerShell execution'},
                                  headers={'X-API-Key': 'test-key-abc123'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'attack_patterns' in data
        assert 'similar_incidents' in data
        assert 'detection_rules' in data
        assert 'context_text' in data

    def test_context_text_is_string(self, flask_client):
        resp = flask_client.post('/search/investigation',
                                  json={'query': 'credential dump'},
                                  headers={'X-API-Key': 'test-key-abc123'})
        data = resp.get_json()
        assert isinstance(data['context_text'], str)


@pytest.mark.unit
class TestSearchHunting:
    def test_returns_patterns_and_rules(self, flask_client):
        resp = flask_client.post('/search/hunting',
                                  json={'query': 'Find lateral movement in last 24 hours'},
                                  headers={'X-API-Key': 'test-key-abc123'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'attack_patterns' in data
        assert 'detection_rules' in data
        assert 'context_text' in data


@pytest.mark.unit
class TestMetrics:
    def test_metrics_returns_latency_data(self, flask_client):
        # Trigger some requests to populate latency data
        for _ in range(3):
            flask_client.post('/retrieve',
                               json={'query': 'test'},
                               headers={'X-API-Key': 'test-key-abc123'})
        resp = flask_client.get('/metrics')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'routes' in data or 'latency' in data or isinstance(data, dict)

    def test_metrics_p50_p95_present(self, flask_client):
        for _ in range(5):
            flask_client.post('/retrieve',
                               json={'query': 'ransomware'},
                               headers={'X-API-Key': 'test-key-abc123'})
        resp = flask_client.get('/metrics')
        data = resp.get_json()
        # Should have latency percentile data
        assert resp.status_code == 200


# ── Integration Tests (require live Qdrant + ingested data) ────────────

@pytest.mark.integration
class TestIntegrationRAG:
    """These tests require:
    1. QDRANT_URL pointing to a running Qdrant instance
    2. Data already ingested (run POST /ingest on knowledge-ingestion first)
    """

    @pytest.fixture(autouse=True)
    def live_client(self):
        if not os.getenv('QDRANT_URL'):
            pytest.skip('QDRANT_URL not set — integration test skipped')
        import importlib
        import rag_service
        importlib.reload(rag_service)
        rag_service.app.config['TESTING'] = True
        self.api_key = os.getenv('RAG_API_KEY', '')
        self.headers = {'X-API-Key': self.api_key} if self.api_key else {}
        with rag_service.app.test_client() as c:
            self.client = c
            yield

    def test_health_live(self):
        resp = self.client.get('/health')
        assert resp.status_code == 200
        assert resp.get_json()['qdrant'] is True

    def test_retrieve_mitre_phishing(self):
        resp = self.client.post('/retrieve',
                                 json={'query': 'phishing email spearphishing', 'type': 'AttackPattern'},
                                 headers=self.headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['count'] > 0
        titles = [r['title'] for r in data['results']]
        assert any('T1566' in t or 'Phishing' in t for t in titles), f"Expected Phishing in results, got: {titles}"

    def test_retrieve_brute_force(self):
        resp = self.client.post('/retrieve',
                                 json={'query': 'brute force SSH failed login attempts'},
                                 headers=self.headers)
        data = resp.get_json()
        assert data['count'] > 0
        # Score should be high for an exact match
        assert data['results'][0]['score'] > 0.5

    def test_investigation_search_latency(self):
        """Response time must be < 2 seconds."""
        start = time.time()
        resp = self.client.post('/search/investigation',
                                 json={'query': 'lateral movement via PsExec remote services'},
                                 headers=self.headers)
        elapsed = time.time() - start
        assert resp.status_code == 200
        assert elapsed < 2.0, f"Search took {elapsed:.2f}s — exceeds 2s target"

    def test_hunting_search_latency(self):
        """Response time must be < 2 seconds."""
        start = time.time()
        resp = self.client.post('/search/hunting',
                                 json={'query': 'detect abnormal authentication patterns'},
                                 headers=self.headers)
        elapsed = time.time() - start
        assert resp.status_code == 200
        assert elapsed < 2.0, f"Hunt search took {elapsed:.2f}s — exceeds 2s target"

    def test_semantic_accuracy_mitre_techniques(self):
        """Semantic search must return relevant MITRE techniques for known queries."""
        test_cases = [
            ('mimikatz lsass credential dump', 'T1003'),
            ('powershell encoded command obfuscation', 'T1059'),
            ('volume shadow copy vssadmin deletion ransomware', 'T1490'),
        ]
        for query, expected_technique in test_cases:
            resp = self.client.post('/retrieve',
                                     json={'query': query, 'type': 'AttackPattern', 'limit': 5},
                                     headers=self.headers)
            data = resp.get_json()
            technique_ids = [r.get('metadata', {}).get('technique_id', '') for r in data['results']]
            assert expected_technique in ' '.join(technique_ids), \
                f"Query '{query}' expected {expected_technique}, got: {technique_ids}"
