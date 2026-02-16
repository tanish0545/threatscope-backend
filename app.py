import os
from dotenv import load_dotenv
from flask import Flask, request, jsonify, redirect, url_for
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle  
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import Image
from reportlab.platypus import ListFlowable, ListItem
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from flask import send_file

from flask_socketio import SocketIO
from authlib.integrations.flask_client import OAuth
from flask_session import Session
from PyPDF2 import PdfReader
import hashlib
import requests
import random
import time
import io

from datetime import datetime, timedelta

# ================= INIT =================
load_dotenv()

app = Flask(__name__)


app.secret_key = os.getenv("SECRET_KEY")

app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = True  # ✅ True in production (HTTPS only)


database_url = os.getenv("DATABASE_URL")

if database_url.startswith("mysql://"):
    database_url = database_url.replace("mysql://", "mysql+pymysql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=12)

app.config['GOOGLE_CLIENT_ID'] = os.getenv("GOOGLE_CLIENT_ID")
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv("GOOGLE_CLIENT_SECRET")

app.config['VT_API_KEY'] = os.getenv("VT_API_KEY")

# ================= CORS LOCK =================
CORS(
    app,
    origins=[os.getenv("FRONTEND_URL")],
    supports_credentials=True
)
db = SQLAlchemy(app)
jwt = JWTManager(app)
socketio = SocketIO(
    app,
    cors_allowed_origins=os.getenv("FRONTEND_URL")
    )
oauth = OAuth(app)

# ================== SECURITY HEADERS =============
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# ================= JWT ERROR HANDLERS =================
@jwt.unauthorized_loader
def unauthorized_callback(callback):
    return jsonify({"error": "Missing or invalid token"}), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({"error": "Session expired"}), 401

# ================= GOOGLE OAUTH =================
oauth.register(
    name='google',
    client_id=app.config["GOOGLE_CLIENT_ID"],
    client_secret=app.config["GOOGLE_CLIENT_SECRET"],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# ================= MODELS =================
class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True)
    name = db.Column(db.String(120))
    picture = db.Column(db.String(500))

class Analysis(db.Model):
    __tablename__ = "analysis"
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255))
    risk = db.Column(db.String(50))
    score = db.Column(db.Integer)
    keywords = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

with app.app_context():
    db.create_all()

# ================= GOOGLE LOGIN =================
@app.route("/auth/google")
def google_login():
    redirect_uri = url_for("google_callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route("/auth/callback")
def google_callback():
    token = oauth.google.authorize_access_token()
    user_info = token["userinfo"]

    email = user_info["email"]
    name = user_info.get("name")
    picture = user_info.get("picture")
    print("GOOGLE PICTURE URL:", picture)

    user = User.query.filter_by(email=email).first()

    if not user:
        user = User(email=email, name=name, picture=picture)
        db.session.add(user)
    else:
        # ✅ ALWAYS update latest Google profile image
        user.name = name
        user.picture = picture

    db.session.commit()

    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={
            "email": email,
            "name": name,
            "picture": picture  # send real google image
        }
    )

    return redirect(f"{os.getenv('FRONTEND_URL')}/?token={access_token}")
# ================= LOCAL ANALYSIS =================
def analyze_content(content):

    keywords_map = {
        "CRITICAL": ["remote code execution", "rce", "credential dumping", "reverse shell"],
        "HIGH": ["malware", "trojan", "backdoor", "ransomware", "exploit"],
        "MEDIUM": ["phishing", "sql injection", "xss", "breach"],
        "LOW": ["scan", "suspicious", "warning"]
    }

    score = 0
    found = []
    text = content.lower()

    for level, words in keywords_map.items():
        for word in words:
            if word in text:
                found.append(word)
                if level == "CRITICAL":
                    score += 100
                elif level == "HIGH":
                    score += 40
                elif level == "MEDIUM":
                    score += 20
                else:
                    score += 5

    if score >= 100:
        risk = "CRITICAL"
    elif score >= 60:
        risk = "HIGH"
    elif score >= 25:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return risk, score, found
# ================= THREAT CLASSIFY =================
def classify_threat(keywords):

    if not keywords:
        return"General Suspicious Activity"
    text = " ".join(keywords).lower()
    
    if any(x in text for x in["ransomware", "trojan", "spyware", "backdoor", "rootkit"]):
        return "Malware"
    
    if any(x in text for x in["phishing", "social engineering", "credential harvesting", "spear phishing", "spear whaling"]):
        return "Social Engineering"
    
    if any(x in text for x in["sql injection", "xss", "csrf", "lfi", "rce"]):
        return "Web Application Attack"
    
    if any(x in text for x in["ddos", "denial of service", "botnet", "flood", "command and control"]):
        return "Network Attack"
    
    if any(x in text for x in["credential", "password", "brute force", "keylogger", "credential dumping"]):
        return "Credential Attack"
    
    if any(x in text for x in["cve", "exploit", "vulnerability", "zero-day", "remote code execution"]):
        return "Vulnerability Exploit"
    
    if any(x in text for x in["scan", "reconnaissance", "suspicious", "warning"]):
        return "Suspicious Activity"
    
    return "General Suspicious Activity"

# ================= VIRUSTOTAL =================
def check_virustotal_hash(file_bytes):

    file_hash = hashlib.sha256(file_bytes).hexdigest()
    headers = {"x-apikey": app.config["VT_API_KEY"]}
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            return stats
    except:
        pass

    return {"malicious": 0, "suspicious": 0, "harmless": 0}

# ================= MOCK AI =================
def mock_ai_analysis(risk, score, keywords):

    time.sleep(random.uniform(2.0, 3.0))
    confidence = random.randint(70, 95)

    return f"""
ThreatScope AI Intelligence Report

Threat Level: {risk}
Confidence: {confidence}%
Score: {score}

Indicators:
{', '.join(keywords)}

Recommendation:
• Immediate monitoring
• Patch vulnerabilities
• Perform full forensic scan
""", confidence

# ================= FILE ANALYZE =================
@app.route("/analyze", methods=["POST"])
@jwt_required()
def analyze():

    user_id = int(get_jwt_identity())
    file = request.files.get("file")
    
    if not file:
        return jsonify({"error": "No file uploaded"}), 400

    file_bytes = file.read()
    filename = file.filename.lower()

    vt_result = check_virustotal_hash(file_bytes)

    content = ""

    if filename.endswith(".pdf"):
        reader = PdfReader(io.BytesIO(file_bytes))
        for page in reader.pages:
            content += page.extract_text() or ""
    else:
        content = file_bytes.decode("utf-8", errors="ignore")

    risk, score, keywords = analyze_content(content)
    category = classify_threat(keywords)
    
    if risk == "CRITICAL":
      socketio.emit("critical_alert", {
            "filename": filename,
            "risk": risk,
            "score": score,
            "keywords": keywords,
            "virustotal": vt_result,
            "category": category
        })

    new_analysis = Analysis(
        filename=filename,
        risk=risk,
        score=score,
        keywords=", ".join(keywords),
        user_id=user_id
    )

    db.session.add(new_analysis)
    db.session.commit()

    return jsonify({
        "risk": risk,
        "score": score,
        "keywords": keywords,
        "virustotal": vt_result,
        "category": category

    })

#================== ANALYZE URL =================
@app.route("/analyze-url", methods=['POST'])
@jwt_required()
def analyze_url():
    user_id = int(get_jwt_identity())
    url = request.json.get("url")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    risk, score, keywords = analyze_content(url)
    category = classify_threat(keywords)

    new_analysis = Analysis(
        filename=url,
        risk=risk,
        score=score,
        keywords=", ".join(keywords),
        user_id=user_id
    )

    db.session.add(new_analysis)
    db.session.commit()

    return jsonify({
        "risk": risk,
        "score": score,
        "keywords": keywords,
        "category": category
    })

# ================= AI ANALYZE =================
@app.route("/ai-analyze", methods=["POST"])
@jwt_required()
def ai_analyze():

    user_id = int(get_jwt_identity())

    file = request.files.get("file")
    url = request.form.get("url")

    if not file and not url:
        return jsonify({"error": "No input"}), 400

    if file:
        content = file.read().decode("utf-8", errors="ignore")
        filename = file.filename
    else:
        content = url
        filename = url

    risk, score, keywords = analyze_content(content)
    category = classify_threat(keywords)
    ai_report, confidence = mock_ai_analysis(risk, score, keywords)

    new_analysis = Analysis(
        filename=filename,
        risk=risk,
        score=score,
        keywords=", ".join(keywords),
        user_id=user_id
    )

    db.session.add(new_analysis)
    db.session.commit()

    return jsonify({
        "risk": risk,
        "score": score,
        "keywords": keywords,
        "ai_summary": ai_report,
        "category": category,
        "confidence": confidence
    })

#=================== AI ANALYZE URL =================
@app.route("/ai-analyze-url", methods=["POST"])
@jwt_required()
def ai_analyze_url():

    user_id = int(get_jwt_identity())
    url = request.json.get("url")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    risk, score, keywords = analyze_content(url)
    category = classify_threat(keywords)
    ai_report, confidence = mock_ai_analysis(risk, score, keywords)

    new_analysis = Analysis(
        filename=url,
        risk=risk,
        score=score,
        keywords=", ".join(keywords),
        user_id=user_id
    )

    db.session.add(new_analysis)
    db.session.commit()

    return jsonify({
        "risk": risk,
        "score": score,
        "keywords": keywords,
        "ai_summary": ai_report,
        "category": category,
        "confidence": confidence
    })

#==================export report =================
@app.route("/export-pdf", methods=["POST"])
@jwt_required()
def export_pdf():

    data = request.get_json()

    filename = data.get("filename", "Unknown")
    risk = data.get("risk", "LOW")
    score = data.get("score", 0)
    category = data.get("category", "General")
    ai_summary = data.get("ai_summary", "")
    confidence = data.get("confidence", 0)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    elements = []

    styles = getSampleStyleSheet()

    # ===== TITLE =====
    title_style = styles["Heading1"]
    title_style.textColor = colors.HexColor("#0d6efd")
    elements.append(Paragraph("ThreatScope Intelligence Report", title_style))
    elements.append(Spacer(1, 0.3 * inch))

    # ===== FILE INFO TABLE =====
    info_data = [
        ["File / URL", filename],
        ["Threat Category", category],
        ["Threat Score", str(score)],
        ["Confidence Score", f"{confidence}%"],
        ["Generated On", datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
    ]

    table = Table(info_data, colWidths=[2.2 * inch, 3.5 * inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.whitesmoke),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10)
    ]))

    elements.append(table)
    elements.append(Spacer(1, 0.4 * inch))

    # ===== RISK COLOR BOX =====
    if risk == "CRITICAL":
        risk_color = colors.red
    elif risk == "HIGH":
        risk_color = colors.orange
    elif risk == "MEDIUM":
        risk_color = colors.yellow
    else:
        risk_color = colors.green

    risk_table = Table([[f"Threat Level: {risk}"]],
                       colWidths=[5.5 * inch],
                       rowHeights=[0.4 * inch])

    risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), risk_color),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTSIZE', (0, 0), (-1, -1), 14)
    ]))

    elements.append(risk_table)
    elements.append(Spacer(1, 0.4 * inch))

    # ===== AI SUMMARY =====
    elements.append(Paragraph("<b>AI Security Analysis:</b>", styles["Heading2"]))
    elements.append(Spacer(1, 0.2 * inch))
    elements.append(Paragraph(ai_summary.replace("\n", "<br/>"), styles["Normal"]))
    elements.append(Spacer(1, 0.5 * inch))

    # ===== FOOTER =====
    elements.append(Paragraph(
        "Generated by ThreatScope AI Security Engine © 2026",
        styles["Italic"]
    ))

    doc.build(elements)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="ThreatScope_Report.pdf",
        mimetype="application/pdf"
    )
#==================== DASHBOARD-STATS =================
@app.route("/dashboard-stats")
@jwt_required()
def dashboard_stats():

    user_id = int(get_jwt_identity())

    total = Analysis.query.filter_by(user_id=user_id).count()
    critical = Analysis.query.filter_by(user_id=user_id, risk="CRITICAL").count()
    high = Analysis.query.filter_by(user_id=user_id, risk="HIGH").count()
    medium = Analysis.query.filter_by(user_id=user_id, risk="MEDIUM").count()
    low = Analysis.query.filter_by(user_id=user_id, risk="LOW").count()

    avg_score = db.session.query(db.func.avg(Analysis.score))\
        .filter(Analysis.user_id == user_id)\
        .scalar() or 0

    return jsonify({
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "avg_score": round(avg_score, 2)
    })#================== DASHBOARD-RECENT =================
@app.route("/dashboard-recent")
@jwt_required()
def dashboard_recent():

    user_id = int(get_jwt_identity())

    records = Analysis.query\
        .filter_by(user_id=user_id)\
        .order_by(Analysis.created_at.desc())\
        .limit(10)\
        .all()

    return jsonify([
        {
            "filename": r.filename,
            "risk": r.risk,
            "score": r.score,
            "time": r.created_at.strftime("%H:%M:%S")
        }
        for r in records
    ])
# ================= HISTORY =================
@app.route("/history")
@jwt_required()
def history():
    user_id = int(get_jwt_identity())
    records = Analysis.query.filter_by(user_id=user_id).all()

    return jsonify([
        {
            "id": r.id,
            "filename": r.filename,
            "risk": r.risk,
            "score": r.score,
            "keywords": r.keywords,
            "created_at": r.created_at.strftime("%Y-%m-%d %H:%M:%S")
        }
        for r in records
    ])

@app.route("/")
def home():
    return "ThreatScope Backend Running 🚀"

if __name__ == "__main__":
    print("🚀 Running server now...")
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)