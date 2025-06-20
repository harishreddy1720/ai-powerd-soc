from fastapi import FastAPI, UploadFile
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import io
import sqlite3
import smtplib
from email.message import EmailMessage

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === Database Setup ===
conn = sqlite3.connect("soc_logs.db", check_same_thread=False)
cursor = conn.cursor()

# Create logs table if it doesn't exist
cursor.execute("""
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_bytes INTEGER,
    dst_bytes INTEGER,
    duration REAL,
    protocol TEXT,
    flag TEXT
)
""")

# Create anomalies table with 'anomaly' and 'score' columns
cursor.execute("""
CREATE TABLE IF NOT EXISTS anomalies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_bytes INTEGER,
    dst_bytes INTEGER,
    duration REAL,
    protocol TEXT,
    flag TEXT,
    anomaly INTEGER,  -- Added 'anomaly' column
    score REAL  -- Added 'score' column
)
""")
conn.commit()

# === Email Alert Function ===
def send_alert_email(anomaly_count):
    msg = EmailMessage()
    msg.set_content(f"{anomaly_count} anomalies detected in recent upload.")
    msg["Subject"] = "[SOC Alert] Anomalies Detected"
    msg["From"] = "sahasrar240@gmail.com"
    msg["To"] = "sahasrar240@gmail.com"

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login("sahasrar240@gmail.com", "svzz ycwm hxcu osvq")  # Use app password
            server.send_message(msg)
    except Exception as e:
        print("Failed to send email:", e)

@app.post("/predict_anomaly/")
async def predict_anomaly(file: UploadFile):
    content = await file.read()
    df = pd.read_csv(io.StringIO(content.decode("utf-8")))

    # Save all logs to DB
    df.to_sql("logs", conn, if_exists='append', index=False)

    # Process features
    features = df.select_dtypes(include=['float64', 'int64']).iloc[:, :5]
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(features)
    model = IsolationForest(contamination=0.01)
    model.fit(X_scaled)
    preds = model.predict(X_scaled)
    df["anomaly"] = preds
    df["score"] = model.decision_function(X_scaled)

    anomalies = df[df["anomaly"] == -1]

    # Save anomalies to DB
    if not anomalies.empty:
        anomalies.to_sql("anomalies", conn, if_exists='append', index=False)
        send_alert_email(len(anomalies))

    return anomalies.to_dict(orient="records")
