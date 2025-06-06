import threading
import time
from GUI import update_gui_with_alert
import winsound

def play_alert_sound():
    winsound.Beep(1000, 500)

def monitor():
    while True:
        alert = "[Snort] Potential threat detected from suspicious IP activity."
        update_gui_with_alert(alert)
        play_alert_sound()
        time.sleep(10)  # Simulate interval

# Keep function name as 'monitor' for import compatibility
