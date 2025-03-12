import multiprocessing
import tkinter as tk
import shutil
import sqlite3
import os
import datetime
import threading
from tkinter import messagebox
from tkinter import simpledialog
from register import initialize_database, register_user, validate_user,update_request_status,get_pending_requests,create_password_reset_request,hash_password,log_password_request_activity

from fileoperations import upload_file,list_user_files, open_file, delete_file

from relations import add_user_relationship,list_related_users

from fileSharing import share_file

from anomalylogoperations import run_anomaly_detection

from backupLogging import backup_file_threaded


from multiprocessing import Process
if __name__ == '__main__':
    DB_NAME = "FileBackup.db"
    DESTINATION_FOLDER = r"C:\\Users\\İzzet\\Desktop\\FileBackupSystem\\Dosyalar\\YüklüDosyalar"
    BACKUP_FOLDER = r"C:\\Users\\İzzet\\Desktop\\FileBackupSystem\\Dosyalar\\YedeklenmişDosyalar"
    USER_LOG_PATH = r"C:\Users\İzzet\Desktop\FileBackupSystem\Dosyalar\Logs\userlog.txt"
    ANOMALYLOG_FILE_PATH=r"C:\Users\İzzet\Desktop\FileBackupSystem\Dosyalar\Logs\anomaly_log.txt"


    initialize_database()
    # def start_anomaly_detection():
    #     anomaly_thread = threading.Thread(target=run_anomaly_detection, daemon=True)
    #     anomaly_thread.start()

    def start_anomaly_detection_process():
        """Anomali tespiti için bir işlem başlatır."""
        anomaly_process = multiprocessing.Process(target=run_anomaly_detection, daemon=True)
        anomaly_process.start()
        


    def show_main_menu():
        
        for widget in root.winfo_children():
            widget.destroy()

        tk.Button(root, text="Login", font=("Arial", 16), command=show_login_screen).pack(pady=20)
        tk.Button(root, text="Register", font=("Arial", 16), command=show_register_screen).pack(pady=20)

    def show_register_screen():
        for widget in root.winfo_children():
            widget.destroy()

        tk.Label(root, text="Register", font=("Arial", 20)).pack(pady=20)

        tk.Label(root, text="Username:", font=("Arial", 14)).pack(pady=5)
        username_entry = tk.Entry(root, font=("Arial", 14))
        username_entry.pack(pady=5)

        tk.Label(root, text="Password:", font=("Arial", 14)).pack(pady=5)
        password_entry = tk.Entry(root, font=("Arial", 14), show="*")
        password_entry.pack(pady=5)

        def register_action():
            username = username_entry.get()
            password = password_entry.get()
            role = "bireyselkullanıcı"  # Sabit rol

            if username == "" or password == "":
                messagebox.showerror("Error", "All fields are required!")
            else:
                success, message = register_user(username, password, role)
                if success:
                    messagebox.showinfo("Success", message)
                    show_main_menu()
                else:
                    messagebox.showerror("Error", message)

        tk.Button(root, text="Register", font=("Arial", 14), command=register_action).pack(pady=20)
        tk.Button(root, text="Back", font=("Arial", 14), command=show_main_menu).pack(pady=10)



    def show_login_screen():
        
        for widget in root.winfo_children():
            widget.destroy()

        tk.Label(root, text="Login", font=("Arial", 20)).pack(pady=20)

        tk.Label(root, text="Username:", font=("Arial", 14)).pack(pady=5)
        username_entry = tk.Entry(root, font=("Arial", 14))
        username_entry.pack(pady=5)

        tk.Label(root, text="Password:", font=("Arial", 14)).pack(pady=5)
        password_entry = tk.Entry(root, font=("Arial", 14), show="*")
        password_entry.pack(pady=5)

        def log_user_activity(username, action="logged in to system", level="INFO"):
            def log_activity():
                """Kullanıcı giriş bilgilerini log dosyasına yazar."""
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

        def login_action():
            username = username_entry.get()
            password = password_entry.get()

            if username == "" or password == "":
                messagebox.showerror("Error", "Username and Password cannot be empty!")
            else:
                success, role, user_id = validate_user(username, password)
                if success:
                    if role == "admin":
                        show_admin_dashboard()
                    elif role == "bireyselkullanıcı":
                        log_user_activity(username)
                        show_user_dashboard(user_id)

                        def check_reset_request_status(user_id):
                            try:
                                conn = sqlite3.connect("FileBackup.db")
                                cursor = conn.cursor()
                                cursor.execute(
                                    "SELECT status FROM password_reset_requests WHERE user_id = ? ORDER BY id DESC LIMIT 1",
                                    (user_id,),
                                )
                                result = cursor.fetchone()
                                conn.close()

                                if result:
                                    status = result[0]
                                    if status == "approved":
                                        return "approved"
                                    elif status == "rejected":
                                        return "rejected"
                                return None
                            except Exception as e:
                                print(f"Error: {str(e)}")
                                return None

                        reset_status = check_reset_request_status(user_id)  # Burada fonksiyonu kullanıyoruz
                        if reset_status == "rejected":
                            messagebox.showerror("Error", "Your password reset request was rejected!")
                else:
                    # Kullanıcıyı kontrol etmek için ikinci bir sorgu yapıyoruz
                    conn = sqlite3.connect("FileBackup.db")
                    cursor = conn.cursor()
                    cursor.execute("SELECT role FROM users WHERE username = ?", (username,))
                    result = cursor.fetchone()
                    conn.close()

                    if result:
                        role = result[0]
                        if role != "admin":
                            log_user_activity(username, action="kullanıcısı hatalı giriş işleminde bulundu.", level="WARNING")
                    messagebox.showerror("Error", "Invalid username or password!")


        tk.Button(root, text="Login", font=("Arial", 14), command=login_action).pack(pady=20)
        tk.Button(root, text="Back", font=("Arial", 14), command=show_main_menu).pack(pady=10)


    def add_notification(message, timestamp):
        """Yeni bir bildirim ekle."""
        conn = sqlite3.connect("FileBackup.db")
        cursor = conn.cursor()
        # Bildirim zaten var mı kontrol et
        cursor.execute(
            "SELECT id FROM admin_notifications WHERE message = ? AND timestamp = ?",
            (message, timestamp)
        )
        if cursor.fetchone() is None:
            cursor.execute(
                "INSERT INTO admin_notifications (message, timestamp) VALUES (?, ?)",
                (message, timestamp)
            )
            conn.commit()
        conn.close()

    def check_anomaly_log():
        """Anomaly log dosyasını kontrol eder ve yeni kayıtları veritabanına ekler."""
        try:
            with open(ANOMALYLOG_FILE_PATH, "r") as log_file:
                logs = log_file.readlines()
                for log in logs:
                    # Satırdaki " -WARNING- " ifadesine göre log'u ayır
                    parts = log.strip().split(" -WARNING- ", 1)
                    
                    # Eğer " -WARNING- " bulunmazsa, bu satırı atla
                    if len(parts) < 2:
                        continue
                    
                    raw_timestamp, raw_message = parts
                    timestamp = raw_timestamp.strip()  # Sadece tarihi alın
                    message = raw_message.strip()  # Mesajı alın
                    add_notification(message, timestamp)
        except FileNotFoundError:
            print(f"{ANOMALYLOG_FILE_PATH} dosyası bulunamadı.")



    def show_admin_notifications():
        """Admin arayüzü: Bildirimleri gösterir."""
        check_anomaly_log()  # Her seferinde yeni anomaly kayıtlarını kontrol et

        for widget in root.winfo_children():
            widget.destroy()

        tk.Label(root, text="Notifications", font=("Arial", 20)).pack(pady=20)

        container = tk.Frame(root)
        container.pack(fill="both", expand=True)

        canvas = tk.Canvas(container)
        scrollbar = tk.Scrollbar(container, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        conn = sqlite3.connect("FileBackup.db")
        cursor = conn.cursor()
        cursor.execute("SELECT id, message, timestamp FROM admin_notifications WHERE status = 'unread'")
        notifications = cursor.fetchall()
        conn.close()

        if not notifications:
            tk.Label(scrollable_frame, text="No new notifications.", font=("Arial", 14)).pack(pady=10)
        else:
            for notif_id, message, timestamp in notifications:
                notif_frame = tk.Frame(scrollable_frame, borderwidth=1, relief="solid")
                notif_frame.pack(pady=5, padx=10, fill="x")

                text = f"{timestamp} - {message}"
                tk.Label(notif_frame, text=text, font=("Arial", 14), wraplength=400, justify="left").pack(side="left", padx=5)
                open_btn = tk.Button(
                    notif_frame, text="Open", font=("Arial", 12),
                    command=lambda nid=notif_id, msg=text: open_notification(nid, msg)
                )
                open_btn.pack(side="right", padx=5)

        tk.Button(root, text="Back", font=("Arial", 14), command=show_admin_dashboard).pack(pady=20)



    def open_notification(notif_id, message):
        """Bir bildirimi aç ve durumunu güncelle."""
        messagebox.showinfo("Notification", message)

        # Bildirimi "read" olarak işaretle
        conn = sqlite3.connect("FileBackup.db")
        cursor = conn.cursor()
        cursor.execute("UPDATE admin_notifications SET status = 'read' WHERE id = ?", (notif_id,))
        conn.commit()
        conn.close()

        show_admin_notifications()



    def show_admin_dashboard():
        """Admin arayüzü."""
        for widget in root.winfo_children():
            widget.destroy()

        tk.Label(root, text="Admin Dashboard", font=("Arial", 20)).pack(pady=20)
        tk.Button(root, text="Notifications", font=("Arial", 14), command=show_admin_notifications).pack(pady=10)


        def get_unique_pending_requests():
            """Tekrarlanan kullanıcı taleplerini filtreleyerek döndürür."""
            try:
                conn = sqlite3.connect("FileBackup.db")
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT MIN(pr.id) AS request_id, u.username
                    FROM password_reset_requests pr
                    JOIN users u ON pr.user_id = u.id
                    WHERE pr.status = 'pending'
                    GROUP BY u.id
                """)
                requests = cursor.fetchall()
                conn.close()
                return requests
            except Exception as e:
                print(f"Error fetching unique pending requests: {str(e)}")
                return []



        def show_password_reset_requests():
            """Admin arayüzü: Şifre değiştirme taleplerini gösterir."""
            for widget in root.winfo_children():
                widget.destroy()

            # Ana frame
            main_frame = tk.Frame(root)
            main_frame.pack(fill="both", expand=1)

            # Canvas ve scrollbar
            canvas = tk.Canvas(main_frame)
            scrollbar = tk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
            scrollable_frame = tk.Frame(canvas)

            # Scrollable frame'i canvas'a ekle
            scrollable_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
            )
            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)

            # Pack canvas ve scrollbar
            canvas.pack(side="left", fill="both", expand=1)
            scrollbar.pack(side="right", fill="y")

            # Başlık
            tk.Label(scrollable_frame, text="Password Reset Requests", font=("Arial", 20)).grid(row=0, column=0, columnspan=3, pady=20)

            
            requests = get_unique_pending_requests()  
            if not requests:
                tk.Label(scrollable_frame, text="No pending requests.", font=("Arial", 14)).grid(row=1, column=0, columnspan=3, pady=10)
            else:
                # Başlıklar
                tk.Label(scrollable_frame, text="Username", font=("Arial", 14, "bold")).grid(row=1, column=0, padx=10, pady=10, sticky="w")
                tk.Label(scrollable_frame, text="Actions", font=("Arial", 14, "bold")).grid(row=1, column=1, padx=10, pady=10, sticky="e")

                for i, (request_id, username) in enumerate(requests, start=2):
                    # Kullanıcı adı
                    tk.Label(scrollable_frame, text=username, font=("Arial", 14)).grid(row=i, column=0, padx=10, pady=5, sticky="w")

                    # Kabul et ve reddet butonları
                    approve_btn = tk.Button(scrollable_frame, text="Approve",bg="green", font=("Arial", 12),
                                            command=lambda rid=request_id: approve_request(rid))
                    approve_btn.grid(row=i, column=1, padx=5, pady=5, sticky="e")

                    reject_btn = tk.Button(scrollable_frame, text="Reject",bg="red", font=("Arial", 12),
                                        command=lambda rid=request_id: reject_request(rid))
                    reject_btn.grid(row=i, column=2, padx=5, pady=5, sticky="e")

            # Geri butonu
            tk.Button(scrollable_frame, text="Back", font=("Arial", 14), command=show_admin_dashboard).grid(row=len(requests) + 2, column=0, columnspan=3, pady=20)




        def set_storage_limit(user_id, new_limit):
            """Bir kullanıcı için depolama limiti belirler."""
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users SET storage_limit = ? WHERE id = ?
            """, (new_limit, user_id))
            conn.commit()
            conn.close()
            messagebox.showinfo("Success", f"Storage limit set to {new_limit} MB for user ID {user_id}.")
            manage_users()

        def ask_limit(user_id):
            """Kullanıcı için yeni bir limit belirleme penceresi."""
            new_limit = simpledialog.askinteger("Set Storage Limit", "Enter new storage limit :")
            if new_limit is not None:
                set_storage_limit(user_id, new_limit)


        def manage_users():
            """Kullanıcıları listele ve yönet (scrollable)."""
            for widget in root.winfo_children():
                widget.destroy()

            
            main_frame = tk.Frame(root)
            main_frame.pack(fill="both", expand=1)

           
            canvas = tk.Canvas(main_frame)
            scrollbar = tk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
            scrollable_frame = tk.Frame(canvas)

            
            scrollable_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
            )
            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)

            
            canvas.pack(side="left", fill="both", expand=1)
            scrollbar.pack(side="right", fill="y")

            
            tk.Label(scrollable_frame, text="User Management", font=("Arial", 20)).grid(row=0, column=0, columnspan=7, pady=20)

            
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, role, storage_limit FROM users WHERE role != 'admin'")
            users = cursor.fetchall()
            conn.close()

            if not users:
                tk.Label(scrollable_frame, text="No users found.", font=("Arial", 14)).grid(row=1, column=0, columnspan=7, pady=10)
            else:
                # Tablo başlıkları
                tk.Label(scrollable_frame, text="ID", font=("Arial", 14, "bold")).grid(row=1, column=0, padx=10, pady=5)
                tk.Label(scrollable_frame, text="Username", font=("Arial", 14, "bold")).grid(row=1, column=1, padx=10, pady=5)
                tk.Label(scrollable_frame, text="Role", font=("Arial", 14, "bold")).grid(row=1, column=2, padx=10, pady=5)
                tk.Label(scrollable_frame, text="Storage Limit (MB)", font=("Arial", 14, "bold")).grid(row=1, column=3, padx=10, pady=5)

                for i, (user_id, username, role, storage_limit) in enumerate(users, start=2):
                    tk.Label(scrollable_frame, text=user_id, font=("Arial", 14)).grid(row=i, column=0, padx=10, pady=5)
                    tk.Label(scrollable_frame, text=username, font=("Arial", 14)).grid(row=i, column=1, padx=10, pady=5)
                    tk.Label(scrollable_frame, text=role, font=("Arial", 14)).grid(row=i, column=2, padx=10, pady=5)
                    tk.Label(scrollable_frame, text=f"{storage_limit} MB", font=("Arial", 14)).grid(row=i, column=3, padx=10, pady=5)

                    # Kullanıcı yönetim butonları
                    tk.Button(scrollable_frame, text="Delete", font=("Arial", 12), bg="red",
                            command=lambda uid=user_id: delete_user(uid)).grid(row=i, column=4, padx=5, pady=5)
                    tk.Button(scrollable_frame, text="Review", font=("Arial", 12), bg="gray",
                            command=lambda uid=user_id: review_user(uid)).grid(row=i, column=5, padx=5, pady=5)
                    tk.Button(scrollable_frame, text="Set Limit", font=("Arial", 12), bg="gray",
                            command=lambda uid=user_id: ask_limit(uid)).grid(row=i, column=6, padx=5, pady=5)

            # Geri butonu
            tk.Button(scrollable_frame, text="Back", font=("Arial", 14), command=show_admin_dashboard).grid(row=len(users) + 2, column=0, columnspan=7, pady=20)




        def delete_user(user_id):
            """Kullanıcıyı sil."""
            confirm = messagebox.askyesno("Confirm", f"Are you sure you want to delete user ID {user_id}?")
            if confirm:
                try:
                    conn = sqlite3.connect(DB_NAME)
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
                    conn.commit()
                    conn.close()
                    messagebox.showinfo("Success", "User deleted successfully!")
                    manage_users()
                except Exception as e:
                    messagebox.showerror("Error", f"An error occurred: {str(e)}")

        tk.Button(root, text="Manage Users", font=("Arial", 14), command=manage_users).pack(pady=10)

        def approve_request(request_id):
            if update_request_status(request_id, "approved"):
                conn = sqlite3.connect("FileBackup.db")
                cursor = conn.cursor()
                cursor.execute("SELECT u.username FROM password_reset_requests pr JOIN users u ON pr.user_id = u.id WHERE pr.id = ?", (request_id,))
                result = cursor.fetchone()
                conn.close()
                
                if result:
                    username = result[0]
                    log_password_request_activity(username, "password reset request approved", level="INFO")
            show_password_reset_requests()

        def reject_request(request_id):
            if update_request_status(request_id, "rejected"):
                conn = sqlite3.connect("FileBackup.db")
                cursor = conn.cursor()
                cursor.execute("SELECT u.username FROM password_reset_requests pr JOIN users u ON pr.user_id = u.id WHERE pr.id = ?", (request_id,))
                result = cursor.fetchone()
                conn.close()
                
                if result:
                    username = result[0]
                    log_password_request_activity(username, "password reset request rejected", level="INFO")
            show_password_reset_requests()

        tk.Button(root, text="Password Reset Requests", font=("Arial", 14), command=show_password_reset_requests).pack(pady=10)
        tk.Button(root, text="Log Files", font=("Arial", 14), command=show_log_files).pack(pady=10)
        tk.Button(root, text="Logout", font=("Arial", 14), command=show_main_menu).pack(pady=10)

        def review_user(user_id):
            """Bir kullanıcının detaylarını incele."""
            for widget in root.winfo_children():
                widget.destroy()

            tk.Label(root, text=f"User Details for ID {user_id}", font=("Arial", 20)).pack(pady=20)

            
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT username, password_hash FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            conn.close()

            if user:
                username, password_hash = user
                tk.Label(root, text=f"Username: {username}", font=("Arial", 14)).pack(pady=10)
                tk.Label(root, text=f"Password Hash: {password_hash}", font=("Arial", 14)).pack(pady=10)

                # Dosyalar butonu
                def show_user_files():
                    """Kullanıcının dosyalarını göster (scrollable)."""
                    for widget in root.winfo_children():
                        widget.destroy()

                    
                    main_frame = tk.Frame(root)
                    main_frame.pack(fill="both", expand=1)

                   
                    canvas = tk.Canvas(main_frame)
                    scrollbar = tk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
                    scrollable_frame = tk.Frame(canvas)

                    
                    scrollable_frame.bind(
                        "<Configure>",
                        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
                    )
                    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
                    canvas.configure(yscrollcommand=scrollbar.set)

                    
                    canvas.pack(side="left", fill="both", expand=1)
                    scrollbar.pack(side="right", fill="y")

                   
                    conn = sqlite3.connect(DB_NAME)
                    cursor = conn.cursor()
                    cursor.execute("SELECT file_name, file_path FROM user_files WHERE user_id = ?", (user_id,))
                    files = cursor.fetchall()
                    conn.close()

                    
                    tk.Label(scrollable_frame, text="User Files" , font=("Arial", 20)).pack(pady=20)
                    
                    if files:
                        for file_name, file_path in files:
                            file_frame = tk.Frame(scrollable_frame)
                            file_frame.pack(pady=5, padx=20, fill="x")

                            tk.Label(file_frame, text=file_name, font=("Arial", 14)).pack(side="left")
                            open_btn = tk.Button(file_frame, text="Open",bg="greesn", font=("Arial", 12),
                                                command=lambda path=file_path: open_file_action(path))
                            open_btn.pack(side="right")
                    else:
                        tk.Label(scrollable_frame, text="No files uploaded.", font=("Arial", 14)).pack(pady=10)

                    
                    tk.Button(scrollable_frame, text="Back", font=("Arial", 14), command=lambda: review_user(user_id)).pack(pady=20)


                tk.Button(root, text="Files", font=("Arial", 14), command=show_user_files).pack(pady=10)

                
                def show_shared_files():
                    """Kullanıcının paylaşılan dosyalarını göster (scrollable)."""
                    for widget in root.winfo_children():
                        widget.destroy()

                    # Ana frame
                    main_frame = tk.Frame(root)
                    main_frame.pack(fill="both", expand=1)

                    # Canvas ve scrollbar
                    canvas = tk.Canvas(main_frame)
                    scrollbar = tk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
                    scrollable_frame = tk.Frame(canvas)

                    # Scrollable frame'i canvas'a ekle
                    scrollable_frame.bind(
                        "<Configure>",
                        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
                    )
                    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
                    canvas.configure(yscrollcommand=scrollbar.set)

                    
                    canvas.pack(side="left", fill="both", expand=1)
                    scrollbar.pack(side="right", fill="y")

                    
                    conn = sqlite3.connect(DB_NAME)
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT f.file_name, u.username 
                        FROM file_shares fs
                        JOIN user_files f ON f.file_path = fs.file_path
                        JOIN users u ON u.id = fs.receiver_id
                        WHERE fs.sender_id = ? OR fs.receiver_id = ?
                    """, (user_id, user_id))
                    shared_files = cursor.fetchall()
                    conn.close()

                    
                    tk.Label(scrollable_frame, text="Shared Files", font=("Arial", 20)).pack(pady=20)

                    if shared_files:
                        for file_name, related_user in shared_files:
                            tk.Label(scrollable_frame, text=f"{file_name} shared with {related_user}", font=("Arial", 14)).pack(pady=5)
                    else:
                        tk.Label(scrollable_frame, text="No shared files.", font=("Arial", 14)).pack(pady=10)

                    
                    tk.Button(scrollable_frame, text="Back", font=("Arial", 14), command=lambda: review_user(user_id)).pack(pady=20)


                tk.Button(root, text="Shared Files", font=("Arial", 14), command=show_shared_files).pack(pady=10)
            else:
                tk.Label(root, text="User not found.", font=("Arial", 14)).pack(pady=10)

            tk.Button(root, text="Back", font=("Arial", 14), command=manage_users).pack(pady=20)

    def show_log_files():
        LOG_FILE_PATH = r"C:\Users\İzzet\Desktop\FileBackupSystem\Dosyalar\Logs\userlog.txt"
        ANOMALY_LOG_PATH = r"C:\Users\İzzet\Desktop\FileBackupSystem\Dosyalar\Logs\anomaly_log.txt"
        """Admin arayüzü: Log dosyalarını gösterir."""
        for widget in root.winfo_children():
            widget.destroy()

        
        main_frame = tk.Frame(root)
        main_frame.pack(fill="both", expand=1)

        
        tk.Label(main_frame, text="Log Files", font=("Arial", 20)).pack(pady=20)
       

       
        log_files = [
            
            ("Anomaly Log", ANOMALY_LOG_PATH),
            
        ]

        
        for i, (log_name, log_path) in enumerate(log_files, start=1):
            frame = tk.Frame(main_frame)
            frame.pack(fill="x", pady=5, padx=20)

            
            tk.Label(frame, text=log_name, font=("Arial", 14)).pack(side="left", padx=10)

            
            tk.Button(frame, text="Open", font=("Arial", 12), bg="blue", fg="white",
                    command=lambda path=log_path: open_log_file(path)).pack(side="right", padx=10)

        
        tk.Button(main_frame, text="Back", font=("Arial", 14), command=show_admin_dashboard).pack(pady=20)


    def open_log_file(file_path):
        """Belirtilen log dosyasını okur ve içeriğini yeni bir pencerede gösterir."""
        try:
            with open(file_path, "r") as file:
                log_content = file.read()
        except Exception as e:
            messagebox.showerror("Error", f"Unable to open file: {str(e)}")
            return

        
        log_window = tk.Toplevel(root)
        log_window.title(f"Log Viewer - {file_path}")
        log_window.geometry("600x400")

        # Scrollable text widget
        text_widget = tk.Text(log_window, wrap="word", font=("Arial", 12))
        text_widget.insert("1.0", log_content)
        text_widget.configure(state="disabled")  # Kullanıcı değişiklik yapamasın
        text_widget.pack(fill="both", expand=1, padx=10, pady=10)

        # Kapat butonu
        tk.Button(log_window, text="Close", font=("Arial", 12), command=log_window.destroy).pack(pady=10)




    # dosya açma
    def open_file_action(file_path):
        success, message = open_file(file_path)
        if success:
            messagebox.showinfo("Success", message)
        else:
            messagebox.showerror("Error", message)


    def delete_file_action(file_id, user_id):
        """Dosyayı sil ve sonucu kullanıcıya göster."""
        confirm = messagebox.askyesno("Confirm", "Are you sure you want to delete this file?")
        if confirm:
            success, message = delete_file(file_id)
            if success:
                messagebox.showinfo("Success", message)
                list_user_files_ui(user_id)  
            else:
                messagebox.showerror("Error", message)


    def list_user_files_ui(user_id):
        """Kullanıcının yüklediği dosyaları listeleyen arayüz."""
        for widget in root.winfo_children():
            widget.destroy()

        tk.Label(root, text="My Files", font=("Arial", 20)).grid(row=0, column=0, columnspan=3, pady=20)

        files = list_user_files(user_id)
        if not files:
            tk.Label(root, text="No files uploaded yet.", font=("Arial", 14)).grid(row=1, column=0, columnspan=3, pady=10)
        else:
            # tk.Label(root, text="File ID", font=("Arial", 14, "bold")).grid(row=1, column=0, padx=10, pady=10)
            tk.Label(root, text="File Name", font=("Arial", 14, "bold")).grid(row=1, column=1, padx=10, pady=10)
            # tk.Label(root, text="File Path", font=("Arial", 14, "bold")).grid(row=1, column=2, padx=10, pady=10)

            for i, (file_id, file_name, file_path) in enumerate(files, start=2):
                # tk.Label(root, text=file_id, font=("Arial", 14)).grid(row=i, column=0, padx=10, pady=5)
                tk.Label(root, text=file_name, font=("Arial", 14)).grid(row=i, column=1, padx=10, pady=5)
                # tk.Label(root, text=file_path, font=("Arial", 14)).grid(row=i, column=2, padx=10, pady=5)
                open_button = tk.Button(root, text="Open",bg="green", font=("Arial", 12), 
                                command=lambda path=file_path: open_file_action(path))
                open_button.grid(row=i, column=3, padx=10, pady=5)


                delete_button = tk.Button(root, text="Delete",bg="red", font=("Arial", 12), 
                                        command=lambda fid=file_id: delete_file_action(fid, user_id))
                delete_button.grid(row=i, column=4, padx=10, pady=5)

        tk.Button(root, text="Back", font=("Arial", 14), command=lambda: show_user_dashboard(user_id)).grid(row=len(files) + 2, column=0, columnspan=3, pady=20)








    def upload_file_ui(user_id):
        """Kullanıcı için dosya yükleme işlemini başlatır."""
        success, message = upload_file(user_id)
        if success:
            messagebox.showinfo("Success", message)
            
            # İzleme işlemini başlat
            
        else:
            messagebox.showerror("Error", message)





    def show_user_dashboard(user_id):
        """Bireysel kullanıcı arayüzü."""
        for widget in root.winfo_children():
            widget.destroy()

        tk.Label(root, text="User Dashboard", font=("Arial", 20)).grid(row=0, column=0, columnspan=3, pady=20)
        

        # Şifre talep ve değiştirme butonlarını üst kısımda yan yana yerleştir
        def check_reset_request_status():
            try:
                conn = sqlite3.connect("FileBackup.db")
                cursor = conn.cursor()
                cursor.execute("SELECT status FROM password_reset_requests WHERE user_id = ? ORDER BY id DESC LIMIT 1", (user_id,))
                result = cursor.fetchone()
                conn.close()

                if result:
                    status = result[0]
                    if status == "approved":
                        return "approved"
                    elif status == "rejected":
                        return "rejected"
                return None
            except Exception as e:
                print(f"Error: {str(e)}")
                return None

        status = check_reset_request_status()

        if status == "approved":
            tk.Button(root, text="Set New Password", font=("Arial", 14), command=lambda: set_new_password(user_id)).grid(row=1, column=0, padx=10, pady=10)
        

        tk.Button(root, text="Request Password Reset", font=("Arial", 14), command=lambda: create_password_reset_request(user_id)).grid(row=2, column=0, padx=10, pady=10)
        tk.Button(root, text="Upload File", font=("Arial", 14), command=lambda: upload_file_ui(user_id)).grid(row=3, column=0, padx=10, pady=10)
        tk.Button(root, text="My Files", font=("Arial", 14), command=lambda: list_user_files_ui(user_id)).grid(row=4, column=0, padx=10, pady=10)
        tk.Button(root, text="Add Member", font=("Arial", 14), command=lambda: add_member_ui(user_id)).grid(row=5, column=0, padx=10, pady=10)
        tk.Button(root, text="My Members", font=("Arial", 14), command=lambda: show_my_members_ui(user_id)).grid(row=6, column=0, padx=10, pady=10)
        tk.Button(root, text="Received files", font=("Arial", 14), command=lambda: show_received_files_ui(user_id)).grid(row=7, column=0, padx=10, pady=10)
        

    # Logout butonunu son satıra ekliyoruz.
        tk.Button(root, text="Logout",bg="red", font=("Arial", 14), command=show_main_menu).grid(row=8, column=0, padx=10, pady=10)




        # Yeni şifre belirleme fonksiyonu
        def set_new_password(user_id):
            for widget in root.winfo_children():
                widget.destroy()

            tk.Label(root, text="Set New Password", font=("Arial", 20)).pack(pady=20)

            tk.Label(root, text="New Password:", font=("Arial", 14)).pack(pady=5)
            new_password_entry = tk.Entry(root, font=("Arial", 14), show="*")
            new_password_entry.pack(pady=5)

            tk.Label(root, text="Confirm New Password:", font=("Arial", 14)).pack(pady=5)
            confirm_password_entry = tk.Entry(root, font=("Arial", 14), show="*")
            confirm_password_entry.pack(pady=5)

            def save_new_password():
                new_password = new_password_entry.get()
                confirm_password = confirm_password_entry.get()

                if new_password == "" or confirm_password == "":
                    messagebox.showerror("Error", "All fields are required!")
                elif new_password != confirm_password:
                    messagebox.showerror("Error", "Passwords do not match!")
                else:
                    # Şifreyi güncelle
                    try:
                        password_hash, salt = hash_password(new_password)
                        conn = sqlite3.connect("FileBackup.db")
                        cursor = conn.cursor()
                        cursor.execute("UPDATE users SET password_hash = ?, salt = ? WHERE id = ?", (password_hash, salt, user_id))
                        conn.commit()
                        conn.close()
                        messagebox.showinfo("Success", "Password updated successfully!")
                        show_user_dashboard(user_id)
                    except Exception as e:
                        print(f"Error: {str(e)}")
                        messagebox.showerror("Error", "An error occurred while updating password!")

            tk.Button(root, text="Save Password", font=("Arial", 14), command=save_new_password).pack(pady=10)
            tk.Button(root, text="Back", font=("Arial", 14), command=lambda: show_user_dashboard(user_id)).pack(pady=10)

        # Kullanıcı adı değiştirme butonu
        tk.Button(root, text="Change Username", font=("Arial", 14), command=lambda: change_username(user_id)).grid(row=2, column=1, padx=10, pady=10)

        # Kullanıcı adı değiştirme fonksiyonu
        def change_username(user_id):
            """Kullanıcı adı ve klasör adını güncelle."""
            for widget in root.winfo_children():
                widget.destroy()

            tk.Label(root, text="Change Username", font=("Arial", 20)).pack(pady=20)

            tk.Label(root, text="New Username:", font=("Arial", 14)).pack(pady=5)
            new_username_entry = tk.Entry(root, font=("Arial", 14))
            new_username_entry.pack(pady=5)

            def save_new_username():
                new_username = new_username_entry.get()

                if new_username == "":
                    messagebox.showerror("Error", "Username cannot be empty!")
                    return

                try:
                    conn = sqlite3.connect(DB_NAME)
                    cursor = conn.cursor()

                    # Eski kullanıcı adını al
                    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
                    old_username_row = cursor.fetchone()
                    if not old_username_row:
                        messagebox.showerror("Error", "User not found!")
                        return

                    old_username = old_username_row[0]

                    old_user_folder = os.path.join(DESTINATION_FOLDER, old_username)
                    old_backup_folder = os.path.join(BACKUP_FOLDER, old_username)
                    new_user_folder = os.path.join(DESTINATION_FOLDER, new_username)
                    new_backup_folder = os.path.join(BACKUP_FOLDER, new_username)

                    if os.path.exists(old_user_folder):
                        os.rename(old_user_folder, new_user_folder)
                    if os.path.exists(old_backup_folder):
                        os.rename(old_backup_folder, new_backup_folder)

                    # Veritabanındaki dosya yollarını güncelle
                    cursor.execute("UPDATE user_files SET file_path = REPLACE(file_path, ?, ?) WHERE file_path LIKE ?", 
                                (old_username, new_username, f"%{old_username}%"))

                    # Kullanıcı adını güncelle
                    cursor.execute("UPDATE users SET username = ? WHERE id = ?", (new_username, user_id))
                    conn.commit()
                    conn.close()

                    messagebox.showinfo("Success", "Username and file paths updated successfully!")
                    show_user_dashboard(user_id)

                except Exception as e:
                    messagebox.showerror("Error", f"An error occurred: {str(e)}")

            tk.Button(root, text="Save Username", font=("Arial", 14), command=save_new_username).pack(pady=10)
            tk.Button(root, text="Back", font=("Arial", 14), command=lambda: show_user_dashboard(user_id)).pack(pady=10)





    def add_member_ui(user_id):
        """Üye ekleme arayüzünü gösterir."""
        for widget in root.winfo_children():
            widget.destroy()

        tk.Label(root, text="Add Member", font=("Arial", 20)).pack(pady=20)

        tk.Label(root, text="Enter Username of the User to Add:", font=("Arial", 14)).pack(pady=5)
        username_entry = tk.Entry(root, font=("Arial", 14))
        username_entry.pack(pady=5)

        def add_member():
            related_username = username_entry.get()
            if related_username == "":
                messagebox.showerror("Error", "Username cannot be empty!")
                return

            # Kullanıcıyı ilişkilendir
            success, message = add_user_relationship(user_id, related_username)
            messagebox.showinfo("Result", message)
            if success:
                show_user_dashboard(user_id)

        tk.Button(root, text="Add",bg="green", font=("Arial", 14), command=add_member).pack(pady=10)
        tk.Button(root, text="Back", font=("Arial", 14), command=lambda: show_user_dashboard(user_id)).pack(pady=10)


    def show_my_members_ui(user_id):
        """Kullanıcının üyelerini listele ve bildirim göster."""
        for widget in root.winfo_children():
            widget.destroy()
        
        tk.Label(root, text="My Members", font=("Arial", 20)).pack(pady=20)

        # Yeni bildirimleri kontrol et ve göster
        show_notifications(user_id)

        members = list_related_users(user_id)

        if not members:
            tk.Label(root, text="You have no members!", font=("Arial", 14)).pack(pady=10)
            tk.Button(root, text="Back", font=("Arial", 14), command=lambda: show_user_dashboard(user_id)).pack(pady=10)
            return

        for member in members:
            member_frame = tk.Frame(root)
            member_frame.pack(fill="x", pady=5)

            tk.Label(member_frame, text=member, font=("Arial", 14)).pack(side="left", padx=10)
            tk.Button(
                member_frame,
                bg="teal",
                text="Share Files",
                font=("Arial", 12),
                command=lambda member=member: show_share_files_ui(user_id, member)
            ).pack(side="right", padx=10)

        tk.Button(root, text="Back", font=("Arial", 14), command=lambda: show_user_dashboard(user_id)).pack(pady=10)

    def show_notifications(user_id):
        """Kullanıcıya yeni bildirimleri göster ve 'seen' olarak işaretle."""
        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            
            # Görülmemiş bildirimleri al
            cursor.execute("""
                SELECT message FROM notifications
                WHERE user_id = ? AND seen = 0
            """, (user_id,))
            notifications = cursor.fetchall()
            
            if notifications:
                for message in notifications:
                    messagebox.showinfo("New Notification", message[0])
                
                # Bildirimleri görüldü olarak işaretle
                cursor.execute("""
                    UPDATE notifications
                    SET seen = 1
                    WHERE user_id = ? AND seen = 0
                """, (user_id,))
                conn.commit()
            
            conn.close()
        except Exception as e:
            print(f"Error in show_notifications: {str(e)}")






    from tkinter import filedialog



    def show_share_files_ui(sender_id, receiver_username):
        """Dosya paylaşımı için arayüz."""
        for widget in root.winfo_children():
            widget.destroy()
        
        tk.Label(root, text=f"Share Files with {receiver_username}", font=("Arial", 20)).pack(pady=20)

        # Kullanıcının dosyalarını al
        sender_username = get_username(sender_id)
        user_files_folder = os.path.join(DESTINATION_FOLDER, sender_username)
        
        if not os.path.exists(user_files_folder):
            tk.Label(root, text="No files to share!", font=("Arial", 14)).pack(pady=10)
            return
        
        files = os.listdir(user_files_folder)
        
        if not files:
            tk.Label(root, text="No files to share!", font=("Arial", 14)).pack(pady=10)
            tk.Button(root, text="Back", font=("Arial", 14), command=lambda: show_user_dashboard(sender_id)).pack(pady=10)

        # Dosya listesi ve gönderme butonları
        for file_name in files:
            file_frame = tk.Frame(root)
            file_frame.pack(fill="x", pady=5)

            tk.Label(file_frame, text=file_name, font=("Arial", 14)).pack(side="left", padx=10)
            tk.Button(
                file_frame,
                text="Send",
                font=("Arial", 12),
                command=lambda file_name=file_name: send_file(sender_id, receiver_username, file_name)
            ).pack(side="right", padx=10)

        tk.Button(root, text="Back", font=("Arial", 14), command=lambda: show_user_dashboard(sender_id)).pack(pady=10)


    def send_file(sender_id, receiver_username, file_name):
        """Seçilen dosyayı gönder."""
        success, message = share_file(sender_id, receiver_username, file_name)
        if success:
            messagebox.showinfo("Success", message)
        else:
            messagebox.showerror("Error", message)




    #dosya paylaşımı için alınan kullanıcı adı

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







    def show_received_files_ui(user_id):
        """Gelen dosyaları göster ve isim değiştirme işlemini destekle."""
        for widget in root.winfo_children():
            widget.destroy()

        tk.Label(root, text="Received Files", font=("Arial", 20)).pack(pady=20)

        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT fs.id, u.username, 
                    COALESCE(fs.modified_name, fs.file_name) AS file_name, 
                    fs.file_path
                FROM file_shares fs
                JOIN users u ON fs.sender_id = u.id
                WHERE fs.receiver_id = ?
            """, (user_id,))
            files = cursor.fetchall()
            conn.close()

            if not files:
                tk.Label(root, text="No files received!", font=("Arial", 14)).pack(pady=10)
                tk.Button(root, text="Back", font=("Arial", 14), command=lambda: show_user_dashboard(user_id)).pack(pady=10)
                return

            for file_id, sender_username, file_name, file_path in files:
                file_frame = tk.Frame(root)
                file_frame.pack(fill="x", pady=5)

                tk.Label(file_frame, text=f"{sender_username} shared: {file_name}", font=("Arial", 14)).pack(side="left", padx=10)
                tk.Button(
                    file_frame,
                    text="Download",
                    bg="green",
                    font=("Arial", 12),
                    command=lambda file_name=file_name, file_path=file_path: download_file(user_id, file_name, file_path)
                ).pack(side="right", padx=10)

                tk.Button(
                    file_frame,
                    text="Rename",
                    bg="blue",
                    font=("Arial", 12),
                    command=lambda file_id=file_id, current_name=file_name: rename_file_ui(user_id, file_id, current_name)
                ).pack(side="right", padx=10)

        except Exception as e:
            tk.Label(root, text=f"Error: {str(e)}", font=("Arial", 14), fg="red").pack(pady=10)

        tk.Button(root, text="Back", font=("Arial", 14), command=lambda: show_user_dashboard(user_id)).pack(pady=10)

    def rename_file_ui(user_id, file_id, current_name):
        """Dosya adını değiştirme arayüzü."""
        for widget in root.winfo_children():
            widget.destroy()

        tk.Label(root, text=f"Rename File: {current_name}", font=("Arial", 20)).pack(pady=20)

        tk.Label(root, text="New Name:", font=("Arial", 14)).pack(pady=5)
        new_name_entry = tk.Entry(root, font=("Arial", 14))
        new_name_entry.pack(pady=5)

        def save_new_name():
            new_name = new_name_entry.get()

            if not new_name.strip():
                messagebox.showerror("Error", "New name cannot be empty!")
                return

            try:
                conn = sqlite3.connect(DB_NAME)
                cursor = conn.cursor()

                # Dosya paylaşımı tablosunda güncelle
                cursor.execute("""
                    UPDATE file_shares SET modified_name = ? WHERE id = ?
                """, (new_name, file_id))

                # Kullanıcı dosyaları tablosunda güncelle
                cursor.execute("""
                    UPDATE user_files SET file_name = ? WHERE file_name = ?
                """, (new_name, current_name))

                conn.commit()
                conn.close()

                messagebox.showinfo("Success", f"File renamed to {new_name}!")
                show_received_files_ui(user_id)

            except Exception as e:
                messagebox.showerror("Error", f"Error renaming file: {str(e)}")

        tk.Button(root, text="Save", font=("Arial", 14), command=save_new_name).pack(pady=10)
        tk.Button(root, text="Back", font=("Arial", 14), command=lambda: show_received_files_ui(user_id)).pack(pady=10)




    def log_download_file_activity(username, action, level="INFO"):
        """Kullanıcı işlem bilgilerini log dosyasına yazar."""
        try:
            with open(USER_LOG_PATH, "a", encoding="utf-8") as log_file:
                current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log_message = f"{current_time} -{level}- {username} {action}\n"
                log_file.write(log_message)
        except Exception as e:
            print(f"Error writing to log file: {str(e)}")




    def download_file(user_id, file_name, file_path):
        """Dosyayı indir ve kullanıcıya kaydet."""
        try:
            # Kullanıcının yüklü dosyalar klasörünü al
            username = get_username(user_id)
            user_folder = os.path.join(DESTINATION_FOLDER, username)

            # Klasör yoksa oluştur
            if not os.path.exists(user_folder):
                os.makedirs(user_folder)

            # Dosyanın hedef yolunu belirle
            destination_path = os.path.join(user_folder, file_name)

            # Dosyayı kopyala
            if not os.path.exists(file_path):
                messagebox.showerror("Error", "File not found on sender's side!")
                return

            with open(file_path, "rb") as src, open(destination_path, "wb") as dest:
                dest.write(src.read())

            # Dosyayı veritabanına kaydet
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT sender_id FROM file_shares WHERE file_path = ? AND receiver_id = ?
            """, (file_path, user_id))
            sender_id = cursor.fetchone()
            
            if sender_id:
                sender_id = sender_id[0]
                sender_username = get_username(sender_id)
            else:
                sender_username = "Unknown"

            cursor.execute("""
                INSERT INTO user_files (user_id, file_name, file_path)
                VALUES (?, ?, ?)
            """, (user_id, file_name, destination_path))
            conn.commit()
            conn.close()

            file_id = cursor.lastrowid
            conn.close()

            # Loglama işlemi
            log_download_file_activity(
                username, 
                f"{sender_username} tarafından gönderilen {file_name} dosyasını indirdi."
            )

            success, backup_message = backup_file_threaded(file_id)
            if not success:
                messagebox.showerror("Error", f"File downloaded but backup failed: {backup_message}")
                return    

            messagebox.showinfo("Success", f"File '{file_name}' downloaded successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Error downloading file: {str(e)}")







    start_anomaly_detection_process()
    # start_anomaly_detection()



    root = tk.Tk()
    root.title("Main Menu")
    root.geometry("900x600")
    root.configure(bg="teal")

    def periodic_check():
        check_anomaly_log()
        root.after(5000, periodic_check)  

    periodic_check()

    show_main_menu()

    root.mainloop()
