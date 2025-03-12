import sqlite3
import os
DB_NAME = "FileBackup.db"
ANOMALY_LOG_PATH = r"C:\Users\İzzet\Desktop\FileBackupSystem\Dosyalar\Logs\anomaly_log.txt"

def add_anomaly_notifications(log_path=ANOMALY_LOG_PATH):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    if os.path.exists(log_path):
        with open(log_path, "r") as f:
            anomalies = f.readlines()
        for anomaly in anomalies:
            
            cursor.execute("SELECT COUNT(*) FROM admin_notifications WHERE message = ?", (anomaly.strip(),))
            if cursor.fetchone()[0] == 0:
                cursor.execute("INSERT INTO admin_notifications (message) VALUES (?)", (anomaly.strip(),))

    conn.commit()
    conn.close()
