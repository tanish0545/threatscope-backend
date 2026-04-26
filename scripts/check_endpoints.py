import requests

urls = [
    'http://127.0.0.1:5000/',
    'http://127.0.0.1:5000/dashboard-stats',
    'http://127.0.0.1:5000/dashboard-recent',
    'http://127.0.0.1:5000/history',
]

for u in urls:
    try:
        r = requests.get(u, timeout=5)
        print(u, '->', r.status_code)
        print(r.text[:800])
    except Exception as e:
        print(u, '-> error', e)
