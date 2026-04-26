from app import app, db, User
from flask_jwt_extended import create_access_token
from datetime import timedelta
import requests

EMAIL = "tester@example.com"

with app.app_context():
    user = User.query.filter_by(email=EMAIL).first()
    if not user:
        user = User(email=EMAIL, name="Test User", picture="")
        db.session.add(user)
        db.session.commit()
        print('Created user id', user.id)
    else:
        print('Using existing user id', user.id)

    token = create_access_token(identity=str(user.id), additional_claims={"email": user.email, "name": user.name, "picture": user.picture}, expires_delta=timedelta(hours=24))

print('\nJWT:')
print(token)

headers = {"Authorization": f"Bearer {token}"}
urls = [
    'http://127.0.0.1:5000/dashboard-stats',
    'http://127.0.0.1:5000/dashboard-recent',
    'http://127.0.0.1:5000/history',
]

for u in urls:
    try:
        r = requests.get(u, headers=headers, timeout=5)
        print('\n', u, '->', r.status_code)
        print(r.text[:1000])
    except Exception as e:
        print(u, '-> error', e)
