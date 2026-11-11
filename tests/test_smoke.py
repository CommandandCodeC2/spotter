"""Smoke tests: every page and endpoint loads, first run works, and data round-trips."""
import io
import json

import pytest

from spotter import create_app

PAGES = ['/', '/network-map', '/reports', '/admin']
STATIC = ['/static/brand.css', '/static/brand.js', '/static/logo.svg',
          '/static/css/dashboard.css', '/static/js/dashboard.js',
          '/static/css/admin.css', '/static/js/admin.js',
          '/static/css/network_map.css', '/static/js/network_map.js',
          '/static/css/reports.css', '/static/js/reports.js']


@pytest.fixture
def app(tmp_path):
    return create_app(data_dir=tmp_path)


@pytest.fixture
def client(app):
    return app.test_client()


def sample_data():
    return {
        "timeline": [
            {"time": "JAN 15 13:00", "title": "Phishing email opened", "tech": "T1566", "severity": "high"},
            {"time": "JAN 15 14:00", "title": "Beacon to C2", "tech": "T1071", "severity": "critical"},
            {"time": "JAN 15 15:00", "title": "Second beacon", "tech": "T1071", "severity": "critical"},
        ],
        "suspicious_ips": [{"ip": "203.0.113.10", "type": "C2", "status": "ACTIVE"}],
        "phishing_domains": [{"domain": "example.invalid", "type": "PHISH"}],
        "file_hashes": [{"hash": "0" * 64, "name": "invoice.pdf.exe", "type": "EXE", "status": "ACTIVE"}],
        "compromised_users": ["user.one", "user.two"],
        "affected_systems": ["WS-01"],
        "reports": [{"id": "IR-0001", "subject": "Test report", "severity": "critical"}],
        "storyboard": [{"title": "Initial Access", "text": "Phishing email."}],
    }


@pytest.mark.parametrize('path', PAGES)
def test_pages_load(client, path):
    response = client.get(path)
    assert response.status_code == 200
    assert b'app-nav' in response.data  # shared navigation is present


@pytest.mark.parametrize('path', STATIC)
def test_static_files_served(client, path):
    assert client.get(path).status_code == 200


def test_first_run_creates_blank_operation(app, tmp_path, client):
    assert (tmp_path / 'data.json').exists()
    assert (tmp_path / 'campaign.json').exists()
    assert (tmp_path / 'uploads').is_dir()

    campaign = client.get('/api/campaign').get_json()
    assert campaign['operation_name'] == 'New Operation'
    assert len(campaign['kill_chain_phases']) == 12

    stats = client.get('/api/stats').get_json()
    assert stats['active_iocs'] == 0
    assert stats['reports'] == 0


def test_existing_files_are_not_overwritten(tmp_path):
    (tmp_path / 'campaign.json').write_text(json.dumps({"operation_name": "Keep Me"}))
    client = create_app(data_dir=tmp_path).test_client()
    campaign = client.get('/api/campaign').get_json()
    assert campaign['operation_name'] == 'Keep Me'
    # Missing settings are filled from defaults
    assert campaign['dashboard_title'] == 'THREAT HUNT DASHBOARD'


def test_data_round_trip_and_stats(client):
    assert client.post('/api/data', json=sample_data()).get_json() == {"success": True}

    data = client.get('/api/data').get_json()
    assert data['reports'][0]['id'] == 'IR-0001'
    assert data['threat_intel'] == []  # missing sections come back empty

    stats = client.get('/api/stats').get_json()
    assert stats == {
        "active_iocs": 3,
        "compromised_users": 2,
        "affected_systems": 1,
        "mitre_techniques": 2,
        "reports": 1,
        "timeline_events": 3,
        "status": "ACTIVE",
    }

    iocs = client.get('/api/iocs').get_json()
    assert [len(iocs[k]) for k in ('ips', 'domains', 'hashes')] == [1, 1, 1]


def test_storyboard_rendered_on_network_map(client):
    client.post('/api/data', json=sample_data())
    page = client.get('/network-map').get_data(as_text=True)
    assert 'Phase 1: Initial Access' in page


def test_storyboard_text_is_escaped(client):
    data = sample_data()
    data['storyboard'] = [{"title": "<script>alert(1)</script>", "text": "x"}]
    client.post('/api/data', json=data)
    page = client.get('/network-map').get_data(as_text=True)
    assert '<script>alert(1)</script>' not in page


def test_campaign_round_trip(client):
    campaign = client.get('/api/campaign').get_json()
    campaign['operation_name'] = 'Exercise Alpha'
    assert client.post('/api/campaign', json=campaign).status_code == 200
    assert client.get('/api/campaign').get_json()['operation_name'] == 'Exercise Alpha'


@pytest.mark.parametrize('endpoint', ['/api/data', '/api/campaign'])
@pytest.mark.parametrize('body', ['not json', '[1, 2, 3]', 'null'])
def test_bad_saves_are_rejected_and_data_kept(client, endpoint, body):
    before = client.get(endpoint).get_json()
    response = client.post(endpoint, data=body, content_type='application/json')
    assert response.status_code == 400
    assert client.get(endpoint).get_json() == before


DIAGRAM = b'''<?xml version="1.0" encoding="UTF-8"?>
<mxfile><diagram><mxGraphModel><root>
  <mxCell id="0"/><mxCell id="1" parent="0"/>
  <mxCell id="2" parent="1" style="ellipse;" value="10.0.0.5" vertex="1" x="300" y="300"/>
  <mxCell id="3" parent="1" style="rounded=1;" value="web-dmz-01" vertex="1" x="600" y="300"/>
</root></mxGraphModel></diagram></mxfile>'''


def test_network_map_upload(client, tmp_path):
    response = client.post('/api/upload-map',
                           data={'file': (io.BytesIO(DIAGRAM), 'network.xml')},
                           content_type='multipart/form-data')
    assert response.status_code == 302
    assert 'success=1' in response.headers['Location']
    assert (tmp_path / 'uploads' / 'network_map.xml').exists()

    page = client.get('/network-map').get_data(as_text=True)
    assert '10.0.0.5' in page
    assert 'web-dmz-01' in page


@pytest.mark.parametrize('file, error', [
    (None, 'no_file'),
    ((io.BytesIO(b'hello'), 'notes.txt'), 'invalid_type'),
])
def test_network_map_upload_rejects_bad_files(client, file, error):
    data = {'file': file} if file else {}
    response = client.post('/api/upload-map', data=data, content_type='multipart/form-data')
    assert response.status_code == 302
    assert f'error={error}' in response.headers['Location']
