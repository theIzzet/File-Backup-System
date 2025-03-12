import sqlite3
import hashlib
import os
import datetime
import threading

DB_NAME = "FileBackup.db"
DESTINATION_FOLDER = r"C:\\Users\\İzzet\\Desktop\\FileBackupSystem\\Dosyalar\\YüklüDosyalar"

def initialize_database():
    """Kullanıcılar ve şifre değişiklik talepleri tablolarını oluşturur."""
    conn = sqlite3.connect("FileBackup.db")
    cursor = conn.cursor()
    # Users tablosu
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'bireyselkullanıcı'))
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_reset_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            file_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

   
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS file_backups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL,
            backup_path TEXT NOT NULL,
            log_path TEXT NOT NULL,
            timestamp DATETIME NOT NULL,
            FOREIGN KEY (file_id) REFERENCES user_files (id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_relationships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            related_user_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (related_user_id) REFERENCES users (id),
            UNIQUE (user_id, related_user_id) -- Aynı ilişkiyi tekrar kaydetmeyi önler
        )
    """)


    cursor.execute("""
    CREATE TABLE IF NOT EXISTS file_shares (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        file_name TEXT NOT NULL,
        file_path TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (sender_id) REFERENCES users (id),
        FOREIGN KEY (receiver_id) REFERENCES users (id)
    )
    """)


    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            seen INTEGER DEFAULT 0, -- 0: Görülmedi, 1: Görüldü
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS admin_notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'unread'
        )
    """)

    # cursor.execute("""
    #     ALTER TABLE file_shares ADD COLUMN modified_name TEXT
    # """)




    
    conn.commit()
    conn.close()


def hash_password(password, salt=None):
    """Şifreyi hashler ve salt üretir."""
    if not salt:
        salt = os.urandom(16).hex()
    password_salted = password + salt
    password_hash = hashlib.sha256(password_salted.encode('utf-8')).hexdigest()
    return password_hash, salt


def register_user(username, password, role):
    """Kullanıcıyı SQLite veritabanına kaydeder."""
    try:
        if role not in ["admin", "bireyselkullanıcı"]:
            return False, "Invalid role!"

        password_hash, salt = hash_password(password)
        conn = sqlite3.connect("FileBackup.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)", 
                       (username, password_hash, salt, role))
        conn.commit()
        conn.close()


        user_folder = os.path.join(DESTINATION_FOLDER, username)
        if not os.path.exists(user_folder):
            os.makedirs(user_folder)


        return True, "User registered successfully!"
    except sqlite3.IntegrityError:
        return False, "Username already exists!"
    except Exception as e:
        return False, f"Error: {str(e)}"


def validate_user(username, password):
    """Kullanıcı giriş bilgilerini doğrular ve rol bilgisi döner."""
    try:
        conn = sqlite3.connect("FileBackup.db")
        cursor = conn.cursor()
        cursor.execute("SELECT id, password_hash, salt, role FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        if result:
            user_id, stored_password_hash, salt, role = result
            input_password_hash, _ = hash_password(password, salt)
            if input_password_hash == stored_password_hash:
                return True, role, user_id  # Doğru değer döndürülüyor
        return False, None, None  # Başarısız girişte 3 değer döner
    except Exception as e:
        print(f"Error: {str(e)}")
        return False, None, None  # Hata durumunda da 3 değer döner


def log_password_request_activity(username, action, level="INFO"):
    def log_activity():
        """Kullanıcı aktivitelerini log dosyasına yazar."""
        log_file_path = r"C:\Users\İzzet\Desktop\FileBackupSystem\Dosyalar\Logs\userlog.txt"
        try:
            with open(log_file_path, "a", encoding="utf-8") as log_file:
                current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log_message = f"{current_time} -{level}- {username} {action}\n"
                log_file.write(log_message)
        except Exception as e:
            print(f"Error writing to log file: {str(e)}")

    log_thread = threading.Thread(target=log_activity, daemon=True)
    log_thread.start()

def get_username(user_id):
    """User ID'sine göre kullanıcı adını döndürür."""
    try:
        conn = sqlite3.connect("FileBackup.db")
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        conn.close()
        if user:
            return user[0]
        return None
    except Exception as e:
        print(f"Error in get_username: {str(e)}")
        return None
    
def create_password_reset_request(user_id):
    """Şifre değiştirme talebi oluşturur."""
    try:
        conn = sqlite3.connect("FileBackup.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO password_reset_requests (user_id, status) VALUES (?, 'pending')", (user_id,))
        conn.commit()
        conn.close()
        username = get_username(user_id)
        
        # Talep loglama
        log_password_request_activity(username, "requested a password reset")


        
        return True, "Password reset request submitted!"
    except Exception as e:
        return False, f"Error: {str(e)}"


def get_pending_requests():
    """Bekleyen şifre değiştirme taleplerini döner."""
    try:
        conn = sqlite3.connect("FileBackup.db")
        cursor = conn.cursor()
        cursor.execute("""
            SELECT pr.id, u.username
            FROM password_reset_requests pr
            JOIN users u ON pr.user_id = u.id
            WHERE pr.status = 'pending'
        """)
        requests = cursor.fetchall()
        conn.close()
        return requests
    except Exception as e:
        print(f"Error: {str(e)}")
        return []


def update_request_status(request_id, status):
    """Şifre değiştirme talebinin durumunu günceller."""
    try:
        conn = sqlite3.connect("FileBackup.db")
        cursor = conn.cursor()
        cursor.execute("UPDATE password_reset_requests SET status = ? WHERE id = ?", (status, request_id))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error: {str(e)}")
        return False




