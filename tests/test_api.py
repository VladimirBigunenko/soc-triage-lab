"""Tests for the Ninja API and dashboard (pytest-django)."""

import pytest

from infra.persistence.incident_store import store


class TestHealthApi:
    def test_health(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"


class TestScanApi:
    def test_scan_populates_store(self, client):
        response = client.post("/api/scan")
        assert response.status_code == 200
        body = response.json()
        assert body["alerts"] > 0
        assert body["incidents"] > 0

    def test_scan_then_stats(self, client):
        client.post("/api/scan")
        response = client.get("/api/stats")
        assert response.status_code == 200
        assert response.json()["incidents"] > 0


class TestIncidentsApi:
    @pytest.fixture(autouse=True)
    def _seed(self):
        store.reset()
        from workers.pipeline import run_pipeline

        run_pipeline(seed=42)
        yield
        store.reset()

    def test_list_incidents(self, client):
        response = client.get("/api/incidents")
        assert response.status_code == 200
        incidents = response.json()
        assert len(incidents) > 0
        first = incidents[0]
        assert {"id", "title", "severity", "status", "alerts_count"} <= set(first)

    def test_incident_detail(self, client):
        response = client.get("/api/incidents")
        incident_id = response.json()[0]["id"]
        detail = client.get(f"/api/incidents/{incident_id}")
        assert detail.status_code == 200
        body = detail.json()
        assert body["alerts"]
        assert "playbook" in body

    def test_incident_not_found(self, client):
        response = client.get("/api/incidents/INC-DOES-NOT-EXIST")
        assert response.status_code == 404

    def test_filter_by_severity(self, client):
        response = client.get("/api/incidents?severity=high")
        assert response.status_code == 200
        assert all(i["severity"] == "HIGH" for i in response.json())


class TestDashboard:
    @pytest.fixture(autouse=True)
    def _seed(self):
        store.reset()
        from workers.pipeline import run_pipeline

        run_pipeline(seed=42)
        yield
        store.reset()

    def test_index_renders(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert b"SOC Triage Lab" in response.content
        assert b"Run demo scan" in response.content

    def test_incident_detail_page(self, client):
        incident_id = store.incidents[0].id
        response = client.get(f"/incident/{incident_id}/")
        assert response.status_code == 200
        assert incident_id.encode() in response.content

    def test_scan_trigger_redirects(self, client):
        response = client.post("/scan/")
        assert response.status_code == 302
        assert store.incidents  # pipeline ran
