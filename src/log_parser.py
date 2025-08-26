import re
from collections import defaultdict
from datetime import datetime, timedelta

# Untuk distributed brute force
ip_tracker = defaultdict(list)
TIME_WINDOW = timedelta(minutes=2)

class SSHLogParser:
    def parse(self, line):
        now = datetime.now()

        # Gagal login
        if "Failed password for" in line:
            match = re.search(r'Failed password for (invalid user )?.* from ([\d.:]+)', line)
            if match:
                ip = match.group(2)

                # Deteksi user tidak valid
                if match.group(1):
                    return {"event": "invalid_user", "ip": ip}

                # Cek distributed brute-force
                ip_tracker[ip].append(now)
                active_ips = [k for k, v in ip_tracker.items() if any(now - t <= TIME_WINDOW for t in v)]
                if len(active_ips) >= 3:
                    return {"event": "distributed_brute_force", "ip": ip}

                return {"event": "failed_ssh", "ip": ip}

        # Sukses login
        elif "Accepted password for" in line:
            match = re.search(r'Accepted password for (\w+) from ([\d.:]+)', line)
            if match:
                username = match.group(1)
                ip = match.group(2)

                # Deteksi login ke root
                if username == "root":
                    return {"event": "login_root", "ip": ip}

                return {"event": "successful_ssh", "ip": ip}

        # Slow brute force (timeout)
        elif "Timeout before authentication" in line:
            match = re.search(r'connection from ([\d.:]+)', line)
            if match:
                return {"event": "slow_brute_force", "ip": match.group(1)}

        return None
