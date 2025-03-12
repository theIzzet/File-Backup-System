# import os
# import time
# import shutil
# import sqlite3
# from watchdog.observers import Observer
# from watchdog.events import FileSystemEventHandler
# from threading import Thread

# DB_NAME = "FileBackup.db"
# BACKUP_FOLDER = r"C:\\Users\\İzzet\\Desktop\\FileBackupSystem\\Dosyalar\\YedeklenmişDosyalar"
# LOG_FOLDER = r"C:\\Users\\İzzet\\Desktop\\FileBackupSystem\\Dosyalar\\Logs"
# DESTINATION_FOLDER = r"C:\\Users\\İzzet\\Desktop\\FileBackupSystem\\Dosyalar\\YüklüDosyalar"

# class FileChangeHandler(FileSystemEventHandler):
#     """
#     Dosya sistemindeki değişiklikleri algılayan sınıf.
#     """
#     def __init__(self, user_id, user_folder):
#         self.user_id = user_id
#         self.user_folder = user_folder

#     def on_modified(self, event):
#         if not event.is_directory:
#             print(f"Modified: {event.src_path}")
#             self.sync_file(event.src_path)

#     def on_created(self, event):
#         if not event.is_directory:
#             print(f"Created: {event.src_path}")
#             self.sync_file(event.src_path)

#     def on_deleted(self, event):
#         if not event.is_directory:
#             print(f"Deleted: {event.src_path}")
#             self.remove_backup(event.src_path)

#     def sync_file(self, src_path):
#         """
#         Değiştirilen veya eklenen dosyayı yedekle.
#         """
#         try:
#             # Kullanıcı klasörü
#             username = os.path.basename(self.user_folder)

#             # Yedekleme klasörüne taşı
#             user_backup_folder = os.path.join(BACKUP_FOLDER, username)
#             if not os.path.exists(user_backup_folder):
#                 os.makedirs(user_backup_folder)

#             file_name = os.path.basename(src_path)
#             backup_path = os.path.join(user_backup_folder, file_name)

#             shutil.copy2(src_path, backup_path)
#             print(f"Synced file to backup: {backup_path}")

#             # Log dosyasını oluştur ve güncelle
#             log_file_path = os.path.join(LOG_FOLDER, f"{username}_backup_log.txt")
#             if not os.path.exists(LOG_FOLDER):
#                 os.makedirs(LOG_FOLDER)

#             with open(log_file_path, "a", encoding="utf-8") as log_file:
#                 log_file.write(f"File Synced: {file_name} | Backup Path: {backup_path} | Timestamp: {time.ctime()}\n")

#             # Veritabanına yedekleme bilgisi ekle
#             conn = sqlite3.connect(DB_NAME)
#             cursor = conn.cursor()
#             cursor.execute("""
#                 UPDATE user_files
#                 SET backup_path = ?, log_path = ?
#                 WHERE file_path = ?
#             """, (backup_path, log_file_path, src_path))
#             conn.commit()
#             conn.close()

#         except Exception as e:
#             print(f"Error syncing file: {str(e)}")

#     def remove_backup(self, src_path):
#         """
#         Silinen dosyanın yedeğini kaldır.
#         """
#         try:
#             username = os.path.basename(self.user_folder)
#             file_name = os.path.basename(src_path)
#             user_backup_folder = os.path.join(BACKUP_FOLDER, username)
#             backup_path = os.path.join(user_backup_folder, file_name)

#             if os.path.exists(backup_path):
#                 os.remove(backup_path)
#                 print(f"Backup removed for: {backup_path}")

#             # Veritabanından dosya kaydını sil
#             conn = sqlite3.connect(DB_NAME)
#             cursor = conn.cursor()
#             cursor.execute("DELETE FROM user_files WHERE file_path = ?", (src_path,))
#             conn.commit()
#             conn.close()

#         except Exception as e:
#             print(f"Error removing backup: {str(e)}")

# def start_file_watcher(user_id):
#     """
#     Dosya değişikliklerini izlemek için bir izleyici başlatır.
#     """
#     conn = sqlite3.connect(DB_NAME)
#     cursor = conn.cursor()
#     cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
#     user_row = cursor.fetchone()
#     conn.close()

#     if not user_row:
#         print(f"User with ID {user_id} not found.")
#         return

#     username = user_row[0]
#     user_folder = os.path.join(DESTINATION_FOLDER, username)

#     if not os.path.exists(user_folder):
#         print(f"User folder does not exist: {user_folder}")
#         return

#     # İzleyici başlat
#     event_handler = FileChangeHandler(user_id, user_folder)
#     observer = Observer()
#     observer.schedule(event_handler, path=user_folder, recursive=True)

#     print(f"Starting file watcher for user {username} at {user_folder}")
#     observer.start()

#     try:
#         while True:
#             time.sleep(1)
#     except KeyboardInterrupt:
#         observer.stop()
#     observer.join()

# # İzleme işlemini bir thread'de başlat
# def start_file_watcher_thread(user_id):
#     watcher_thread = Thread(target=start_file_watcher, args=(user_id,))
#     watcher_thread.daemon = True
#     watcher_thread.start()


import os
import time
import shutil
import sqlite3
from multiprocessing import Process
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

DB_NAME = "FileBackup.db"
BACKUP_FOLDER = r"C:\\Users\\İzzet\\Desktop\\FileBackupSystem\\Dosyalar\\YedeklenmişDosyalar"
LOG_FOLDER = r"C:\\Users\\İzzet\\Desktop\\FileBackupSystem\\Dosyalar\\Logs"
DESTINATION_FOLDER = r"C:\\Users\\İzzet\\Desktop\\FileBackupSystem\\Dosyalar\\YüklüDosyalar"

class FileChangeHandler(FileSystemEventHandler):
    def __init__(self, user_id, user_folder):
        self.user_id = user_id
        self.user_folder = user_folder

    def on_modified(self, event):
        if not event.is_directory:
            print(f"Modified: {event.src_path}")
            self.sync_file(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            print(f"Created: {event.src_path}")
            self.sync_file(event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            print(f"Deleted: {event.src_path}")
            self.remove_backup(event.src_path)

    def sync_file(self, src_path):
        try:
            username = os.path.basename(self.user_folder)
            user_backup_folder = os.path.join(BACKUP_FOLDER, username)
            if not os.path.exists(user_backup_folder):
                os.makedirs(user_backup_folder)

            file_name = os.path.basename(src_path)
            backup_path = os.path.join(user_backup_folder, file_name)

            shutil.copy2(src_path, backup_path)
            print(f"Synced file to backup: {backup_path}")

            log_file_path = os.path.join(LOG_FOLDER, f"{username}_backup_log.txt")
            if not os.path.exists(LOG_FOLDER):
                os.makedirs(LOG_FOLDER)

            with open(log_file_path, "a", encoding="utf-8") as log_file:
                log_file.write(f"File Synced: {file_name} | Backup Path: {backup_path} | Timestamp: {time.ctime()}\n")

            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE user_files
                SET backup_path = ?, log_path = ?
                WHERE file_path = ?
            """, (backup_path, log_file_path, src_path))
            conn.commit()
            conn.close()

        except Exception as e:
            print(f"Error syncing file: {str(e)}")

    def remove_backup(self, src_path):
        try:
            username = os.path.basename(self.user_folder)
            file_name = os.path.basename(src_path)
            user_backup_folder = os.path.join(BACKUP_FOLDER, username)
            backup_path = os.path.join(user_backup_folder, file_name)

            if os.path.exists(backup_path):
                os.remove(backup_path)
                print(f"Backup removed for: {backup_path}")

            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM user_files WHERE file_path = ?", (src_path,))
            conn.commit()
            conn.close()

        except Exception as e:
            print(f"Error removing backup: {str(e)}")

def start_file_watcher(user_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    user_row = cursor.fetchone()
    conn.close()

    if not user_row:
        print(f"User with ID {user_id} not found.")
        return

    username = user_row[0]
    user_folder = os.path.join(DESTINATION_FOLDER, username)

    if not os.path.exists(user_folder):
        print(f"User folder does not exist: {user_folder}")
        return

    event_handler = FileChangeHandler(user_id, user_folder)
    observer = Observer()
    observer.schedule(event_handler, path=user_folder, recursive=True)

    print(f"Starting file watcher for user {username} at {user_folder}")
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

def start_file_watcher_process(user_id):
    process = Process(target=start_file_watcher, args=(user_id,))
    process.start()
    