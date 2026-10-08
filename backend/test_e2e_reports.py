import io
from fastapi.testclient import TestClient
from main import app, _create_token, _read_users, _write_users

client = TestClient(app)

users = _read_users()
admin_username = 'admin_01'
regular_username = 'test_report_user'

# Ensure regular test user exists with User role
users[regular_username] = {
    'username': regular_username,
    'full_name': 'Test Report User',
    'email': 'report_user@test.local',
    'role': 'User',
    'is_active': True,
    'is_blocked': False,
    'created_at': '2026-10-05T00:00:00',
}
_write_users(users)

admin_token = _create_token(admin_username)
user_token = _create_token(regular_username)

admin_headers = {'Authorization': f'Bearer {admin_token}'}
user_headers = {'Authorization': f'Bearer {user_token}'}

print('=== TEST 1: Admin Report Endpoints ===')
admin_endpoints = [
    '/api/admin/reports/security?date_range=30d',
    '/api/admin/reports/threats?date_range=30d',
    '/api/admin/reports/users?date_range=30d',
    '/api/admin/reports/audit?date_range=30d',
    '/api/admin/reports/incidents?date_range=30d',
    '/api/admin/reports/activity?date_range=30d',
]
for ep in admin_endpoints:
    res = client.get(ep, headers=admin_headers)
    assert res.status_code == 200, f'Failed {ep}: {res.status_code} {res.text}'
    data = res.json()
    clean_ep = ep.split('?')[0]
    print(f'PASS: GET {clean_ep} (records: {data.get("record_count", 0)})')

print('\n=== TEST 2: Admin PDF & Excel Export Endpoints ===')
admin_types = ['security_overview', 'threat_intelligence', 'user_security', 'audit_log', 'incidents', 'chat_activity']
for rtype in admin_types:
    # PDF
    res_pdf = client.post('/api/admin/reports/pdf', json={'report_type': rtype, 'date_range': '30d'}, headers=admin_headers)
    assert res_pdf.status_code == 200, f'Admin PDF {rtype} failed: {res_pdf.status_code} {res_pdf.text}'
    assert res_pdf.headers.get('content-type') == 'application/pdf'
    assert len(res_pdf.content) > 1000, f'PDF {rtype} too small'

    # Excel
    res_xlsx = client.post('/api/admin/reports/excel', json={'report_type': rtype, 'date_range': '30d'}, headers=admin_headers)
    assert res_xlsx.status_code == 200, f'Admin Excel {rtype} failed: {res_xlsx.status_code} {res_xlsx.text}'
    assert len(res_xlsx.content) > 1000, f'Excel {rtype} too small'
    print(f'PASS: Admin export {rtype} -> PDF ({len(res_pdf.content)} bytes) & Excel ({len(res_xlsx.content)} bytes)')

print('\n=== TEST 3: User Report Endpoints ===')
user_endpoints = [
    '/api/user/reports/security?date_range=30d',
    '/api/user/reports/history?date_range=30d',
    '/api/user/reports/activity?date_range=30d',
    '/api/user/reports/alerts?date_range=30d',
]
for ep in user_endpoints:
    res = client.get(ep, headers=user_headers)
    assert res.status_code == 200, f'Failed {ep}: {res.status_code} {res.text}'
    data = res.json()
    clean_ep = ep.split('?')[0]
    print(f'PASS: GET {clean_ep} (records: {data.get("record_count", 0)})')

print('\n=== TEST 4: User PDF & Excel Export Endpoints ===')
user_types = ['personal_security', 'security_history', 'my_chat_activity', 'security_alerts']
for rtype in user_types:
    res_pdf = client.post('/api/user/reports/pdf', json={'report_type': rtype, 'date_range': '30d'}, headers=user_headers)
    assert res_pdf.status_code == 200, f'User PDF {rtype} failed: {res_pdf.status_code}'
    assert res_pdf.headers.get('content-type') == 'application/pdf'
    assert len(res_pdf.content) > 1000

    res_xlsx = client.post('/api/user/reports/excel', json={'report_type': rtype, 'date_range': '30d'}, headers=user_headers)
    assert res_xlsx.status_code == 200, f'User Excel {rtype} failed: {res_xlsx.status_code}'
    assert len(res_xlsx.content) > 1000
    print(f'PASS: User export {rtype} -> PDF ({len(res_pdf.content)} bytes) & Excel ({len(res_xlsx.content)} bytes)')

print('\n=== TEST 5: RBAC & Permission Enforcement ===')
unauthorized_res = client.get('/api/admin/reports/security', headers=user_headers)
assert unauthorized_res.status_code == 403, f'Expected 403 Forbidden for non-admin, got {unauthorized_res.status_code}'
print('PASS: Regular user blocked from Admin report endpoint (HTTP 403 Forbidden)')

unauthorized_post = client.post('/api/admin/reports/pdf', json={'report_type': 'security_overview'}, headers=user_headers)
assert unauthorized_post.status_code == 403, f'Expected 403 Forbidden for non-admin PDF, got {unauthorized_post.status_code}'
print('PASS: Regular user blocked from Admin PDF export endpoint (HTTP 403 Forbidden)')

no_auth_res = client.get('/api/user/reports/security')
assert no_auth_res.status_code == 401, f'Expected 401 Unauthorized for missing token, got {no_auth_res.status_code}'
print('PASS: Anonymous request blocked (HTTP 401 Unauthorized)')

print('\n=== TEST 6: Report Generation History Endpoints ===')
hist_admin = client.get('/api/admin/reports/history', headers=admin_headers)
assert hist_admin.status_code == 200
print(f'PASS: Admin report history retrieved ({hist_admin.json().get("total", 0)} total records)')

hist_user = client.get('/api/user/reports/generation-history', headers=user_headers)
assert hist_user.status_code == 200
print(f'PASS: User report history retrieved ({hist_user.json().get("total", 0)} total records)')

print('\n=== ALL END-TO-END REPORT & EXPORT TESTS COMPLETED SUCCESSFULLY! ===')
