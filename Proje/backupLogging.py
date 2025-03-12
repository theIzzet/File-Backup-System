import sqlite3
import datetime
import shutil
import os
import threading
from datetime import datetime

DB_NAME = "FileBackup.db"
BACKUP_FOLDER = r"C:\\Users\\İzzet\\Desktop\\FileBackupSystem\\Dosyalar\\YedeklenmişDosyalar"
LOG_FILE_PATH = r"C:\\Users\\İzzet\\Desktop\\FileBackupSystem\\Dosyalar\\Logs\\backup_log.txt"

def backup_file_threaded(file_id):
    def backup_operation():
        success, message = _backup_file(file_id)
        if success:
            print(f"Backup succeeded: {message}")
        else:
            print(f"Backup failed: {message}")

    thread = threading.Thread(target=backup_operation)
    thread.start()

    
    return True, f"Backup thread started for file ID {file_id}."


def _backup_file(file_id):
    """
    Dosya yedekleme işlemi. Bu fonksiyon bir thread içinde çalıştırılır.
    :param file_id: Yedeklenecek dosyanın veritabanındaki benzersiz ID'si.
    :return: (bool, str) Başarı durumu ve mesaj.
    """
    try:
        
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT uf.file_path, u.username
            FROM user_files uf
            JOIN users u ON uf.user_id = u.id
            WHERE uf.id = ?
        """, (file_id,))
        file_row = cursor.fetchone()
        conn.close()

        if not file_row:
            log_event("backup", "FileNotFound", f"File ID {file_id} not found in the database.", "Error", 0)
            return False, f"[Error] File with ID {file_id} not found in the database."

        file_path, username = file_row
        if not os.path.exists(file_path):
            log_event("backup", "FileNotFound", f"File {file_path} not found in the filesystem.", "Error", 0)
            return False, f"[Error] File {file_path} not found in the filesystem."

        # Kullanıcıya özel yedek klasörü oluştur
        user_backup_folder = os.path.join(BACKUP_FOLDER, username)
        if not os.path.exists(user_backup_folder):
            os.makedirs(user_backup_folder)

        # Dosyayı yedekleme klasörüne kopyala
        file_name = os.path.basename(file_path)
        backup_path = os.path.join(user_backup_folder, file_name)
        shutil.copy2(file_path, backup_path)

        # Veritabanına yedekleme bilgilerini ekle
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO file_backups (file_id, backup_path, log_path, timestamp) 
            VALUES (?, ?, ?, ?)
        """, (file_id, backup_path, LOG_FILE_PATH, datetime.now()))
        conn.commit()
        conn.close()

        # Log dosyasına başarı mesajı yaz
        log_event(
            "backup",
            "Success",
            f"File {file_name} successfully backed up to {backup_path}.",
            "Success",
            os.path.getsize(file_path),
            username=username,
            source_path=file_path
        )
        return True, f"[Success] File {file_name} backed up successfully to {backup_path}!"
    except Exception as e:
        log_event("backup", "Error", f"Error during backup for file ID {file_id}: {str(e)}", "Error", 0)
        return False, f"[Error] Error during backup for file ID {file_id}: {str(e)}"


def log_event(operation, status_code, message, status, data_size, username="Unknown", source_path="Unknown"):
    """
    Log dosyasına bir işlem kaydı ekler.
    :param operation: Yapılan işlemin türü (örneğin: 'backup').
    :param status_code: İşlemle ilgili durum kodu.
    :param message: İşlemle ilgili açıklama mesajı.
    :param status: İşlem durumu ('Success', 'Error', vb.).
    :param data_size: Yedeklenen veri miktarı (byte cinsinden).
    :param username: İşlemi gerçekleştiren kullanıcı adı.
    :param source_path: İşlemle ilgili kaynak dizin.
    """
    try:
        start_time = datetime.now()  # İşlem başlangıç zamanı
        end_time = datetime.now()  # İşlem bitiş zamanı (örnek senaryo)
        log_entry = (
            f"Start Time: {start_time} | End Time: {end_time} | "
            f"Operation: {operation} | Status Code: {status_code} | "
            f"Message: {message} | Status: {status} | "
            f"User: {username} | Source Path: {source_path} | "
            f"Data Size: {data_size} bytes\n"
        )
        with open(LOG_FILE_PATH, "a", encoding="utf-8") as log_file:
            log_file.write(log_entry)
    except Exception as e:
        print(f"[Error] Unable to write to log file: {str(e)}")
