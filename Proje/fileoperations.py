import os
import sqlite3
import threading
from tkinter import filedialog, messagebox
import platform
import subprocess
import shutil
import datetime 

from file_watcher import start_file_watcher_process
from backupLogging import backup_file_threaded

DB_NAME = "FileBackup.db"
DESTINATION_FOLDER = r"C:\\Users\\İzzet\\Desktop\\FileBackupSystem\\Dosyalar\\YüklüDosyalar"

USER_LOG_PATH = r"C:\Users\İzzet\Desktop\FileBackupSystem\Dosyalar\Logs\userlog.txt"

def open_file(file_path):
    """Belirtilen dosyayı sistemin varsayılan uygulaması ile açar."""
    try:
        if platform.system() == "Windows":
            os.startfile(file_path)  # Windows için
        elif platform.system() == "Darwin":  # MacOS
            subprocess.run(["open", file_path])
        else:  # Linux
            subprocess.run(["xdg-open", file_path])
        return True, "File opened successfully."
    except Exception as e:
        return False, f"Error opening file: {str(e)}"



def delete_file(file_id):
    """
    Belirtilen dosyayı veritabanından ve fiziksel dosya sisteminden siler.
    :param file_id: Silinecek dosyanın veritabanındaki benzersiz ID'si.
    :return: (True, "Başarılı mesaj") veya (False, "Hata mesajı")
    """
    try:
        # Veritabanından dosya yolunu al
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT file_path FROM user_files WHERE id = ?
        """, (file_id,))
        file_row = cursor.fetchone()

        # Eğer dosya bulunamazsa hata ver
        if not file_row:
            conn.close()
            return False, "File not found in the database."

        file_path = file_row[0]  # Veritabanından alınan fiziksel dosya yolu

        # Dosya fiziksel olarak varsa sil
        if os.path.exists(file_path):
            os.remove(file_path)  # Dosyayı fiziksel olarak sil

        # Veritabanındaki kaydı sil
        cursor.execute("""
            DELETE FROM user_files WHERE id = ?
        """, (file_id,))
        conn.commit()
        conn.close()

        return True, "File deleted successfully!"
    except Exception as e:
        return False, f"Error deleting file: {str(e)}"




def log_upload_file_activity(username, action, level="INFO"):
    def log_activity():
        """Kullanıcı işlem bilgilerini log dosyasına yazar."""
        try:
            with open(USER_LOG_PATH, "a", encoding="utf-8") as log_file:
                current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log_message = f"{current_time} -{level}- {username} {action}\n"
                log_file.write(log_message)
        except Exception as e:
            print(f"Error writing to log file: {str(e)}")
    
    log_thread = threading.Thread(target=log_activity, daemon=True)
    log_thread.start()

def upload_file(user_id):
    """Kullanıcının bir dosya yüklemesini sağlar, kendi klasörüne kaydeder ve veritabanına işler."""
    # Kullanıcının adını, depolama limitini ve mevcut depolama kullanımını al
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT username, storage_limit, 
               COALESCE((SELECT SUM(LENGTH(file_path)) / 1048576.0 FROM user_files WHERE user_id = ?), 0) AS used_storage
        FROM users WHERE id = ?
    """, (user_id, user_id))
    user_data = cursor.fetchone()
    conn.close()

    if not user_data:
        return False, "User not found!"

    username, storage_limit, used_storage = user_data
    user_folder = os.path.join(DESTINATION_FOLDER, username)

    # Kullanıcıya özel klasörün var olup olmadığını kontrol et
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)
    
    


    file_path = filedialog.askopenfilename(title="Select a File")
    if not file_path:
        return False, "No file selected."
    


    file_name = os.path.basename(file_path)
    destination_path = os.path.join(user_folder, file_name)
    
    if os.path.exists(destination_path):
        return False, f"A file with the name '{file_name}' already exists."

    # Dosya boyutunu kontrol et
    file_size_mb = os.path.getsize(file_path) / 1048576.0
    if used_storage + file_size_mb > storage_limit:
        return False, f"Storage limit exceeded! Used: {used_storage:.2f} MB / {storage_limit} MB. File size: {file_size_mb:.2f} MB."

    try:
        # Dosya adını al ve hedef yolu oluştur
        file_name = os.path.basename(file_path)
        destination_path = os.path.join(user_folder, file_name)

        # Dosyayı kopyala
        shutil.copy2(file_path, destination_path)

        # Veritabanına kaydet
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO user_files (user_id, file_name, file_path)
            VALUES (?, ?, ?)
        """, (user_id, file_name, destination_path))
        conn.commit()
        file_id = cursor.lastrowid

        # Kullanıcının mevcut depolama kullanımını güncelle
        cursor.execute("""
            UPDATE users SET current_storage_mb = COALESCE((SELECT SUM(LENGTH(file_path)) / 1048576.0 FROM user_files WHERE user_id = ?), 0)
            WHERE id = ?
        """, (user_id, user_id))
        conn.commit()
        conn.close()

        # Dosya yükleme işlemini logla
        log_upload_file_activity(username, f"{file_name} adlı dosyayı yükledi.")

        # Dosyayı otomatik olarak yedekle
        success, backup_message = backup_file_threaded(file_id)
        if not success:
            return False, f"File uploaded, but backup failed: {backup_message}"

        start_file_watcher_process(user_id)

        return True, f"File uploaded and backed up successfully !"
    except Exception as e:
        return False, f"Error uploading file: {str(e)}"


def list_user_files(user_id):
    """Belirli bir kullanıcının yüklediği dosyaları listeler."""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, file_name, file_path
            FROM user_files
            WHERE user_id = ?
        """, (user_id,))
        files = cursor.fetchall()
        conn.close()
        return files
    except Exception as e:
        print(f"Error: {str(e)}")
        return []


