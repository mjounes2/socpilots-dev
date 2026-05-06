"""
SOCPilots Knowledge Ingestion — Unit & Integration Tests

Run unit tests (no external deps):
  pytest services/knowledge-ingestion/tests/test_ingestion.py -v -m unit

Run integration tests (needs Qdrant + TheHive + OpenSearch):
  QDRANT_URL=http://localhost:6333 THEHIVE_URL=... pytest ... -m integration
"""

import os
import sys
import json
import time
import pytest
from unittest.mock import patch, MagicMock, call

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


# ── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def mock_qdrant_client():
    client = MagicMock()
    client.get_collections.return_value = MagicMock(collections=[])
    client.get_collection.return_value = MagicMock(points_count=0)
    count_result = MagicMock()
    count_result.count = 0
    client.count.return_value = count_result
    return client


@pytest.fixture
def mock_model():
    model = MagicMock()
    model.encode.return_value = [0.0] * 384
    return model


@pytest.fixture
def ingest_service(mock_qdrant_client, mock_model):
    with patch.dict(os.environ, {
        'QDRANT_URL': 'http://mock:6333',
        'THEHIVE_URL': 'http://mock-hive:9000',
        'THEHIVE_API_KEY': 'mock-key',
        'OPENSEARCH_URL': 'http://mock-os:9200',
        'OPENSEARCH_USER': 'admin',
        'OPENSEARCH_PASS': 'pass',
    }):
        with patch('qdrant_client.QdrantClient', return_value=mock_qdrant_client), \
             patch('sentence_transformers.SentenceTransformer', return_value=mock_model):
            import importlib
            import knowledge_ingest
            importlib.reload(knowledge_ingest)
            svc = knowledge_ingest.KnowledgeIngestionService()
            return svc


@pytest.fixture
def flask_client(mock_qdrant_client, mock_model):
    with patch.dict(os.environ, {
        'QDRANT_URL': 'http://mock:6333',
        'RAG_API_KEY': 'ingest-key-xyz',
        'THEHIVE_URL': 'http://mock-hive:9000',
        'THEHIVE_API_KEY': 'mock-key',
    }):
        with patch('qdrant_client.QdrantClient', return_value=mock_qdrant_client), \
             patch('sentence_transformers.SentenceTransformer', return_value=mock_model):
            import importlib
            import app as ingest_app
            importlib.reload(ingest_app)
            ingest_app.app.config['TESTING'] = True
            with ingest_app.app.test_client() as c:
                yield c


# ── Unit Tests — MITRE Ingestion ───────────────────────────────────────

@pytest.mark.unit
class TestMitreIngestion:
    def test_mitre_count_at_least_50(self, ingest_service):
        count = ingest_service.ingest_mitre_attack_patterns()
        assert count >= 50, f"Expected at least 50 MITRE techniques, got {count}"

    def test_mitre_calls_upsert_per_technique(self, ingest_service, mock_qdrant_client):
        count = ingest_service.ingest_mitre_attack_patterns()
        assert mock_qdrant_client.upsert.call_count == count

    def test_mitre_upsert_has_correct_payload_fields(self, ingest_service, mock_qdrant_client):
        ingest_service.ingest_mitre_attack_patterns()
        call_args = mock_qdrant_client.upsert.call_args_list[0]
        points = call_args.kwargs.get('points') or call_args[1].get('points') or call_args[0][1]
        point = points[0] if hasattr(points, '__iter__') else points
        payload = point.payload
        assert 'id' in payload
        assert 'title' in payload
        assert 'content' in payload
        assert 'type' in payload
        assert payload['type'] == 'AttackPattern'
        assert payload['source'] == 'mitre'

    def test_mitre_embedding_called_per_technique(self, ingest_service, mock_model):
        ingest_service.ingest_mitre_attack_patterns()
        assert mock_model.encode.call_count >= 50

    def test_mitre_ids_are_stable_across_runs(self, ingest_service):
        """Point IDs must be deterministic (same input → same ID)."""
        id1 = ingest_service._point_id("mitre:T1566")
        id2 = ingest_service._point_id("mitre:T1566")
        assert id1 == id2
        assert isinstance(id1, int)
        assert 0 < id1 < 2**63


# ── Unit Tests — Detection Rules Ingestion ─────────────────────────────

@pytest.mark.unit
class TestDetectionRulesIngestion:
    def test_builtin_rules_ingested(self, ingest_service):
        with patch.object(ingest_service, '_fetch_wazuh_rules', return_value=[]):
            count = ingest_service.ingest_detection_rules()
        assert count >= 15, f"Expected ≥15 built-in rules, got {count}"

    def test_rule_payload_has_rule_id(self, ingest_service, mock_qdrant_client):
        with patch.object(ingest_service, '_fetch_wazuh_rules', return_value=[]):
            ingest_service.ingest_detection_rules()
        for c in mock_qdrant_client.upsert.call_args_list:
            points = c.kwargs.get('points') or c[0][1] if c[0] else c[1].get('points', [])
            for p in (points if isinstance(points, list) else [points]):
                if hasattr(p, 'payload') and p.payload.get('type') == 'DetectionRule':
                    meta = json.loads(p.payload.get('metadata', '{}'))
                    assert 'rule_id' in meta
                    break


# ── Unit Tests — Response Procedures Ingestion ────────────────────────

@pytest.mark.unit
class TestResponseProceduresIngestion:
    def test_response_procedures_count(self, ingest_service):
        count = ingest_service.ingest_response_procedures()
        assert count >= 10, f"Expected ≥10 response procedures, got {count}"

    def test_response_procedures_type(self, ingest_service, mock_qdrant_client):
        ingest_service.ingest_response_procedures()
        types = set()
        for c in mock_qdrant_client.upsert.call_args_list:
            points = c.kwargs.get('points') or []
            for p in (points if isinstance(points, list) else [points]):
                if hasattr(p, 'payload'):
                    types.add(p.payload.get('type'))
        assert 'ResponseProcedure' in types


# ── Unit Tests — Incident Reports Ingestion ───────────────────────────

@pytest.mark.unit
class TestIncidentReportsIngestion:
    def test_skips_when_no_thehive_config(self):
        with patch.dict(os.environ, {'THEHIVE_URL': '', 'THEHIVE_API_KEY': ''}):
            with patch('qdrant_client.QdrantClient'), \
                 patch('sentence_transformers.SentenceTransformer'):
                import importlib
                import knowledge_ingest
                importlib.reload(knowledge_ingest)
                svc = knowledge_ingest.KnowledgeIngestionService()
                count = svc.ingest_incident_reports()
                assert count == 0

    def test_handles_thehive_connection_error(self, ingest_service):
        with patch('requests.post', side_effect=ConnectionError("refused")):
            count = ingest_service.ingest_incident_reports()
            assert count == 0  # should not raise, should return 0


# ── Unit Tests — Run Ingestion Orchestration ──────────────────────────

@pytest.mark.unit
class TestRunIngestion:
    def test_run_all_sources(self, ingest_service):
        with patch.object(ingest_service, 'ingest_mitre_attack_patterns', return_value=55) as m1, \
             patch.object(ingest_service, 'ingest_detection_rules', return_value=20) as m2, \
             patch.object(ingest_service, 'ingest_historical_incidents', return_value=10) as m3, \
             patch.object(ingest_service, 'ingest_incident_reports', return_value=5) as m4, \
             patch.object(ingest_service, 'ingest_response_procedures', return_value=10) as m5:
            results = ingest_service.run_ingestion()
        assert results['total'] == 100
        assert results['mitre_techniques'] == 55
        m1.assert_called_once()
        m2.assert_called_once()

    def test_run_selective_sources(self, ingest_service):
        with patch.object(ingest_service, 'ingest_mitre_attack_patterns', return_value=55) as m1, \
             patch.object(ingest_service, 'ingest_detection_rules', return_value=20) as m2, \
             patch.object(ingest_service, 'ingest_historical_incidents', return_value=0) as m3:
            results = ingest_service.run_ingestion(sources=['mitre', 'rules'])
        m1.assert_called_once()
        m2.assert_called_once()
        m3.assert_not_called()
        assert results['mitre_techniques'] == 55

    def test_setup_vector_index_called(self, ingest_service, mock_qdrant_client):
        with patch.object(ingest_service, 'ingest_mitre_attack_patterns', return_value=0), \
             patch.object(ingest_service, 'ingest_detection_rules', return_value=0), \
             patch.object(ingest_service, 'ingest_historical_incidents', return_value=0), \
             patch.object(ingest_service, 'ingest_incident_reports', return_value=0), \
             patch.object(ingest_service, 'ingest_response_procedures', return_value=0):
            ingest_service.run_ingestion()
        # create_collection should have been called (setup_vector_index)
        assert mock_qdrant_client.create_collection.called or \
               mock_qdrant_client.get_collections.called


# ── Unit Tests — Flask API ────────────────────────────────────────────

@pytest.mark.unit
class TestIngestAPI:
    def test_ingest_requires_api_key(self, flask_client):
        resp = flask_client.post('/ingest', json={})
        assert resp.status_code == 401

    def test_ingest_wrong_key_rejected(self, flask_client):
        resp = flask_client.post('/ingest',
                                  json={},
                                  headers={'X-API-Key': 'wrong'})
        assert resp.status_code == 401

    def test_health_no_auth_required(self, flask_client):
        resp = flask_client.get('/health')
        assert resp.status_code in (200, 503)  # OK or Qdrant down

    def test_stats_no_auth_required(self, flask_client):
        resp = flask_client.get('/stats')
        assert resp.status_code == 200

    def test_ingest_with_valid_key(self, flask_client):
        resp = flask_client.post('/ingest',
                                  json={'sources': ['mitre']},
                                  headers={'X-API-Key': 'ingest-key-xyz'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['status'] == 'ok'
        assert 'results' in data


# ── Integration Tests ─────────────────────────────────────────────────

@pytest.mark.integration
class TestIntegrationIngestion:
    @pytest.fixture(autouse=True)
    def check_env(self):
        if not os.getenv('QDRANT_URL'):
            pytest.skip('QDRANT_URL not set')

    def test_full_ingestion_pipeline(self):
        import importlib
        import knowledge_ingest
        importlib.reload(knowledge_ingest)
        svc = knowledge_ingest.KnowledgeIngestionService()
        results = svc.run_ingestion(sources=['mitre', 'rules', 'response_procedures'])
        assert results['mitre_techniques'] >= 50
        assert results['detection_rules'] >= 15
        assert results['response_procedures'] >= 10
        assert results['total'] >= 75

    def test_ingestion_performance(self):
        import importlib
        import knowledge_ingest
        importlib.reload(knowledge_ingest)
        svc = knowledge_ingest.KnowledgeIngestionService()
        start = time.time()
        svc.run_ingestion(sources=['mitre'])
        elapsed = time.time() - start
        assert elapsed < 60, f"MITRE ingestion took {elapsed:.1f}s — exceeds 60s limit"

    def test_stats_after_ingestion(self):
        import importlib
        import knowledge_ingest
        importlib.reload(knowledge_ingest)
        svc = knowledge_ingest.KnowledgeIngestionService()
        svc.run_ingestion(sources=['mitre'])
        stats = svc.get_stats()
        assert stats.get('total', 0) > 0
        assert 'AttackPattern' in stats
