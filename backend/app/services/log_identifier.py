def detect_log_type(file_path):

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        sample = f.read(500)

    if "HTTP/" in sample:
        return "Apache/Nginx"

    if "sshd" in sample or "Failed password" in sample:
        return "SSH"

    return "Unknown"