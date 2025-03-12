import time
import datetime
import os
LOG_FILE_PATH = r"C:\Users\İzzet\Desktop\FileBackupSystem\Dosyalar\Logs\userlog.txt"
ANOMALY_LOG_PATH = r"C:\Users\İzzet\Desktop\FileBackupSystem\Dosyalar\Logs\anomaly_log.txt"
STATE_FILE_PATH = r"C:\Users\İzzet\Desktop\FileBackupSystem\Dosyalar\Logs\state.txt"


def read_state():
    """Durum dosyasından last_processed_line değerini okur."""
    if os.path.exists(STATE_FILE_PATH):
        with open(STATE_FILE_PATH, "r", encoding="utf-8") as state_file:
            content = state_file.read().strip()
            if content.isdigit():  # İçeriğin bir sayı olduğundan emin olun
                return int(content)
    return 0  # Varsayılan olarak 0 döndür



def write_state(last_line):
    """Durum dosyasına last_processed_line değerini yazar."""
    with open(STATE_FILE_PATH, "w", encoding="utf-8") as state_file:
        state_file.write(str(last_line))


def read_log_file():
    """Log dosyasındaki tüm verileri okur."""
    with open(LOG_FILE_PATH, "r", encoding="utf-8") as log_file:
        return log_file.readlines()


def write_anomaly_log(anomalies):
    """Yeni anomalileri anomali log dosyasına tarih ile birlikte yazar."""
    existing_anomalies = read_anomaly_log()
    with open(ANOMALY_LOG_PATH, "w", encoding="utf-8") as anomaly_log:
        for anomaly in existing_anomalies:
            anomaly_log.write(f"{anomaly}\n")
        for anomaly in anomalies:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            anomaly_log.write(f"{timestamp} {anomaly}\n")



def read_anomaly_log():
    """Anomali log dosyasındaki mevcut verileri okur."""
    if os.path.exists(ANOMALY_LOG_PATH):
        with open(ANOMALY_LOG_PATH, "r", encoding="utf-8") as anomaly_log:
            return [line.strip() for line in anomaly_log.readlines()]
    return []


def detect_anomalies():
    """Log dosyasını okur ve anomali tespiti yapar."""
    last_processed_line = read_state()
    log_lines = read_log_file()

    new_lines = log_lines[last_processed_line:]
    new_anomalies = []

    # Tüm anomali kontrollerini çağır
    new_anomalies += check_failed_logins(new_lines)
    new_anomalies += check_multiple_reset_requests(new_lines)
    new_anomalies += check_multiple_file_uploads(new_lines)
    new_anomalies += check_multiple_file_downloads(new_lines)


    if new_anomalies:
        write_anomaly_log(new_anomalies)

    # Durumu güncelle
    write_state(len(log_lines))


def check_failed_logins(log_lines, time_window=180, max_attempts=3):
    """Başarısız giriş denemelerini kontrol eder."""
    login_attempts = {}
    new_anomalies = []
    
    for line in log_lines:
        if "WARNING" in line and "hatalı giriş işleminde bulundu" in line:
            timestamp_str = line.split(" -")[0]
            timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            username = line.split("- ")[1].split(" kullanıcısı")[0].strip()
            
            if username not in login_attempts:
                login_attempts[username] = []
            login_attempts[username].append(timestamp)
    
    # Anomalileri kontrol et
    for username, attempts in login_attempts.items():
        attempts.sort()
        for i in range(len(attempts) - max_attempts + 1):
            time_diff = (attempts[i + max_attempts - 1] - attempts[i]).total_seconds()
            if time_diff <= time_window:
                message = f"-WARNING- {username} made more than {max_attempts} consecutive failed login attempts."
                new_anomalies.append(message)
                break

    return new_anomalies

def check_multiple_reset_requests(log_lines, time_window=180):
    """Kullanıcının art arda şifre değiştirme taleplerini kontrol eder."""
    reset_requests = {}
    new_anomalies = []
    
    for line in log_lines:
        if "INFO" in line and "requested a password reset" in line:
            timestamp_str = line.split(" -")[0]
            timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            username = line.split("- ")[1].split(" ")[0].strip()
            
            if username not in reset_requests:
                reset_requests[username] = []
            reset_requests[username].append(timestamp)
    
    # Anomalileri kontrol et
    for username, requests in reset_requests.items():
        requests.sort()
        for i in range(len(requests) - 2):  # 3'ten fazla talep için kontrol yapıyoruz
            time_diff = (requests[i + 2] - requests[i]).total_seconds()  # 3. talep ile ilk talep arasındaki fark
            if time_diff <= time_window:  # 3 talep 3 dk içinde ise anomali olarak kaydedelim
                message = f"-WARNING- {username} made more than 3 password reset requests within {time_window//60} minutes."
                new_anomalies.append(message)
                break  

    return new_anomalies


def check_multiple_file_uploads(log_lines, time_window=60):
    """Kullanıcının art arda dosya yüklemelerini kontrol eder."""
    file_uploads = {}
    new_anomalies = []

    for line in log_lines:
        if "INFO" in line and "dosyayı yükledi" in line:
            timestamp_str = line.split(" -")[0]
            timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            username = line.split("- ")[1].split(" ")[0].strip()

            if username not in file_uploads:
                file_uploads[username] = []
            file_uploads[username].append(timestamp)
    
    # Anomalileri kontrol et
    for username, uploads in file_uploads.items():
        uploads.sort()
        for i in range(len(uploads) - 2):  
            time_diff = (uploads[i + 2] - uploads[i]).total_seconds()  
            if time_diff <= time_window: 
                message = f"-WARNING- {username} uploaded more than 3 files within {time_window//60} minutes."
                new_anomalies.append(message)
                break  # İlk anomaliyi bulduktan sonra duruyoruz

    return new_anomalies




def check_multiple_file_downloads(log_lines, time_window=60, max_downloads=3):
    """Bir kullanıcı 1 dakika içinde 3'ten fazla dosya indirirse anomaliyi kontrol eder."""
    download_events = {}
    new_anomalies = []

    for line in log_lines:
        if "INFO" in line and "dosyasını indirdi" in line:
            timestamp_str = line.split(" -")[0]
            timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            username = line.split("- ")[1].split(" ")[0].strip()

            if username not in download_events:
                download_events[username] = []
            download_events[username].append(timestamp)

    # Anomalileri kontrol et
    for username, downloads in download_events.items():
        downloads.sort()
        for i in range(len(downloads) - max_downloads + 1):
            time_diff = (downloads[i + max_downloads - 1] - downloads[i]).total_seconds()
            if time_diff <= time_window:
                message = f"-WARNING- {username} downloaded more than {max_downloads} files within 1 minute."
                new_anomalies.append(message)
                break

    return new_anomalies

def get_new_log_lines(log_lines):
    """Log dosyasındaki yeni satırları döndürür."""
    global last_processed_line
    new_lines = log_lines[last_processed_line:]
    last_processed_line += len(new_lines)
    return new_lines



def run_anomaly_detection():
    """Anomali tespiti sürecini başlatır ve sürekli çalışmasını sağlar."""
    while True:
        detect_anomalies()
        time.sleep(5)  
