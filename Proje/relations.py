import sqlite3
import datetime
from tkinter import messagebox
DB_NAME = "FileBackup.db"

def log_user_activity(username, action, level="INFO"):
    """Kullanıcı aktivitelerini log dosyasına yazar."""
    log_file_path = r"C:\Users\İzzet\Desktop\FileBackupSystem\Dosyalar\Logs\userlog.txt"
    try:
        with open(log_file_path, "a", encoding="utf-8") as log_file:
            current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_message = f"{current_time} - {level} - {username} {action}\n"
            log_file.write(log_message)
    except Exception as e:
        print(f"Error writing to log file: {str(e)}")



def add_user_relationship(user_id, related_username):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        # İlişkili kullanıcının ID'sini al
        cursor.execute("SELECT id, username FROM users WHERE username = ?", (related_username,))
        related_user = cursor.fetchone()
        
        if not related_user:
            return False, "Related user not found!"
        
        related_user_id, related_user_username = related_user
        
        # Birinci yön: Kullanıcı -> İlişkili Kullanıcı
        cursor.execute("""
            INSERT INTO user_relationships (user_id, related_user_id)
            VALUES (?, ?)
        """, (user_id, related_user_id))

        # İkinci yön: İlişkili Kullanıcı -> Kullanıcı
        cursor.execute("""
            INSERT INTO user_relationships (user_id, related_user_id)
            VALUES (?, ?)
        """, (related_user_id, user_id))
        
        # Kullanıcı adlarını al
        username = get_username(user_id)

        # Log dosyasına yaz
        log_user_activity(username, f"{related_user_username}'yi arkadaş olarak ekledi.")

        # Kullanıcıya bildirim gönder
        message = f"{username} kişisi sizi üye olarak ekledi. Artık ilişkilisiniz."
        cursor.execute("""
            INSERT INTO notifications (user_id, message)
            VALUES (?, ?)
        """, (related_user_id, message))
        
        conn.commit()
        conn.close()

        return True, f"{related_username} artık üyeniz ve karşılıklı olarak ilişki kuruldu!"
    except sqlite3.IntegrityError:
        return False, "Bu kullanıcı zaten üyeniz veya ilişki zaten mevcut!"
    except Exception as e:
        return False, f"Error: {str(e)}"





def list_related_users(user_id):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.username 
            FROM user_relationships r
            JOIN users u ON r.related_user_id = u.id
            WHERE r.user_id = ?
        """, (user_id,))
        related_users = cursor.fetchall()
        conn.close()
        return [user[0] for user in related_users]
    except Exception as e:
        print(f"Error: {str(e)}")
        return []


def notify_user(member_username, owner_username):
    """Kullanıcıya bildirim gönderir."""
    messagebox.showinfo(
        "Membership Notification",
        f"You have been added as a member by {owner_username}."
    )
def get_username(user_id):
    """Verilen user_id ile kullanıcının kullanıcı adını döndürür."""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        
        conn.close()

        if user:
            return user[0]  # Kullanıcı adını döndür
        return None
    except Exception as e:
        print(f"Error in get_username: {str(e)}")
        return None
