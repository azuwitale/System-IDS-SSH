from flask import Blueprint, render_template
import os

dashboard_bp = Blueprint('main', __name__)

@dashboard_bp.route('/')
def index():
    alerts = []
    log_path = os.path.join(os.path.dirname(__file__),'..', 'alert.log')
    log_path = os.path.abspath(log_path)

    try:
        with open(log_path, "r") as f:
            for line in f:
                # Pastikan format log punya " - " agar bisa di-split
                if " - " in line:
                    timestamp, message = line.strip().split(" - ", 1)
                    alerts.append({
                        "time": timestamp,
                        "message": message
                    })
    except Exception as e:
        print(f"[ERROR] Gagal baca alert.log: {e}")

    return render_template("index.html", alerts=alerts)
