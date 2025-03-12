import sqlite3
import os
from datetime import datetime
DB_NAME = "FileBackup.db"
DESTINATION_FOLDER = r"C:\\Users\\İzzet\\Desktop\\FileBackupSystem\\Dosyalar\\YüklüDosyalar"


def log_share_activity(username, action, level="INFO"):
    """Kullanıcı aktivitelerini log dosyasına yazar."""
    log_file_path = r"C:\Users\İzzet\Desktop\FileBackupSystem\Dosyalar\Logs\userlog.txt"
    try:
        with open(log_file_path, "a", encoding="utf-8") as log_file:
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_message = f"{current_time} - {level} - {username} {action}\n"
            log_file.write(log_message)
    except Exception as e:
        print(f"Error writing to log file: {str(e)}")


def share_file(sender_id, receiver_username, file_name):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        # Alıcı kullanıcının ID'sini al
        cursor.execute("SELECT id FROM users WHERE username = ?", (receiver_username,))
        receiver = cursor.fetchone()
        
        if not receiver:
            return False, "Receiver user not found!"
        
        receiver_id = receiver[0]
        
        # Paylaşılacak dosyanın yolunu al
        file_path = os.path.join(DESTINATION_FOLDER, get_username(sender_id), file_name)
        
        if not os.path.exists(file_path):
            return False, "File not found!"

        # Dosya paylaşımını kaydet
        cursor.execute("""
            INSERT INTO file_shares (sender_id, receiver_id, file_name, file_path)
            VALUES (?, ?, ?, ?)
        """, (sender_id, receiver_id, file_name, file_path))
        
        conn.commit()
        conn.close()

        # Loglama işlemi
        sender_username = get_username(sender_id)
        log_share_activity(sender_username, f"sent file '{file_name}' to {receiver_username}")
        
        return True, f"File '{file_name}' shared successfully with {receiver_username}!"
    except Exception as e:
        return False, f"Error: {str(e)}"


def get_username(user_id):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        # Kullanıcı adı sorgusu
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        
        conn.close()
        
        if user:
            return user[0]  # Kullanıcı adı döndürülüyor
        else:
            return None  # Kullanıcı bulunamadıysa None döndür
    except Exception as e:
        print(f"Error in get_username: {str(e)}")
        return None
