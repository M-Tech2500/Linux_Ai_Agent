import os
import subprocess
import logging
import re
import json
import threading
import psutil
import time
import shlex
from functools import partial  # Added import for proper lambda capture

# Replace PyQt5 imports with PyQt6 imports:
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit,
    QLineEdit, QPushButton, QMessageBox, QInputDialog, QProgressDialog, QTabWidget
)
from PyQt6.QtCore import QTimer, Qt, QEvent, QThread, pyqtSignal, QSize
from PyQt6.QtGui import QPainter, QColor, QFont, QLinearGradient  # add QLinearGradient
import sys

try:
    import GPUtil  # Optional: for GPU monitoring
except ImportError:
    GPUtil = None

from google import genai
from google.genai import types

# --- 0. Logging configuration ---
# Log information is displayed in the 'gemini_sys_assistant.log' file and also in the console.
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler("gemini_sys_assistant.log"),
                        logging.StreamHandler() # Display log in console
                    ])

logging.info("Gemini System Assistant started.")

# --- User trusted commands file configuration ---
USER_TRUSTED_COMMANDS_FILE = 'user_trusted_commands.json'
# This list is loaded empty at first and then read from the file
user_trusted_commands = [] 

def load_user_trusted_commands():
    """Loads the user trusted commands from a JSON file."""
    global user_trusted_commands
    if os.path.exists(USER_TRUSTED_COMMANDS_FILE):
        try:
            with open(USER_TRUSTED_COMMANDS_FILE, 'r', encoding='utf-8') as f:
                user_trusted_commands = json.load(f)
            logging.info(f"User trusted commands loaded from '{USER_TRUSTED_COMMANDS_FILE}'.")
        except json.JSONDecodeError as e:
            logging.error(f"Error reading JSON file of trusted commands: {e}")
            user_trusted_commands = [] # Clears the list to prevent corrupted data
        except Exception as e:
            logging.error(f"Unknown error loading trusted commands: {e}")
            user_trusted_commands = []
    else:
        logging.info("User trusted commands file not found. A new list will be created.")
        user_trusted_commands = []

def save_user_trusted_commands():
    """Saves the user trusted commands to a JSON file."""
    try:
        with open(USER_TRUSTED_COMMANDS_FILE, 'w', encoding='utf-8') as f:
            json.dump(user_trusted_commands, f, indent=4, ensure_ascii=False)
        logging.info(f"User trusted commands saved to '{USER_TRUSTED_COMMANDS_FILE}'.")
    except Exception as e:
        logging.error(f"Error saving user trusted commands: {e}")

# --- 2. System information gathering functions ---
def get_disk_usage():
    """Returns disk space using 'df -h'."""
    try:
        result = subprocess.run(['df', '-h'], capture_output=True, text=True, check=True)
        return "Disk Space:\n" + result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Error getting disk space: {e.stderr}")
        return f"Error getting disk space: {e.stderr}"

def get_memory_usage():
    """Returns memory usage using 'free -h'."""
    try:
        result = subprocess.run(['free', '-h'], capture_output=True, text=True, check=True)
        return "Memory Usage:\n" + result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Error getting memory usage: {e.stderr}")
        return f"Error getting memory usage: {e.stderr}"

def get_running_processes():
    """Returns top 10 processes by memory usage using 'ps aux'."""
    try:
        result = subprocess.run(['ps', 'aux', '--sort=-%mem'], capture_output=True, text=True, check=True)
        lines = result.stdout.splitlines()
        return "Top 10 Processes by Memory Usage:\n" + "\n".join(lines[:11]) # Includes header
    except subprocess.CalledProcessError as e:
        logging.error(f"Error getting processes: {e.stderr}")
        return f"Error getting processes: {e.stderr}"

def get_network_interfaces():
    """Returns network interfaces status using 'ip a' or 'ifconfig'."""
    try:
        result = subprocess.run(['ip', 'a'], capture_output=True, text=True, check=True)
        return "Network Interfaces Status:\n" + result.stdout
    except FileNotFoundError:
        logging.warning("Command 'ip' not found. Trying 'ifconfig'.")
        try:
            result = subprocess.run(['ifconfig'], capture_output=True, text=True, check=True)
            return "Network Interfaces Status (using ifconfig):\n" + result.stdout
        except FileNotFoundError:
            logging.error("Neither 'ip' nor 'ifconfig' found.")
            return "Error: Network commands (ip/ifconfig) not found."
        except subprocess.CalledProcessError as e:
            logging.error(f"Error getting network status (ifconfig): {e.stderr}")
            return f"Error getting network status (ifconfig): {e.stderr}"
    except subprocess.CalledProcessError as e:
        logging.error(f"Error getting network status (ip): {e.stderr}")
        return f"Error getting network status (ip): {e.stderr}"

def get_system_uptime():
    """Returns system uptime using 'uptime'."""
    try:
        result = subprocess.run(['uptime'], capture_output=True, text=True, check=True)
        return "System Uptime:\n" + result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Error getting uptime: {e.stderr}")
        return f"Error getting uptime: {e.stderr}"

# --- 3. Safe command execution module (use with caution) ---
# This section is responsible for executing the suggested commands by Gemini.
# **Extremely important: Only non-destructive and approved commands should be whitelisted.**
# This list uses regular expression patterns to match safe commands.
# Adding new patterns should be done with caution and full awareness of security implications.
SAFE_COMMANDS_WHITELIST = [
    r'^ls$', r'^ls\s.*', # ls, ls -l, ls /path
    r'^cd\s[a-zA-Z0-9_/.\-]+$', r'^pwd$', # cd /path, pwd
    r'^cat\s+/[a-zA-Z0-9_/\.\-]+$', # cat /etc/os-release, cat /proc/cpuinfo (only specific and defined files)
    r'^df$', r'^df\s-h$', # df, df -h
    r'^free$', r'^free\s-h$', # free, free -h
    r'^ps$', r'^ps\saux.*', # ps, ps aux, ps aux --sort=-%mem
    r'^ip\sa$', r'^ifconfig$', # ip a, ifconfig
    r'^uptime$', # uptime
    r'^echo\s.*', # echo "hello world"
    r'^whoami$', # whoami
    r'^hostname$', # hostname
    # Administrative and system commands with caution:
    # apt commands: install with multiple packages, update, upgrade, remove, purge, clean, autoremove
    r'^sudo\s+apt\s+update$',
    r'^sudo\s+apt\s+upgrade$',
    r'^sudo\s+apt\s+install\s+[\w\s\-]+$', # Modified: Allow multiple package names separated by spaces
    r'^sudo\s+apt\s+remove\s+[\w\s\-]+$', # Modified: Allow multiple package names
    r'^sudo\s+apt\s+purge\s+[\w\s\-]+$', # Modified: Allow multiple package names
    r'^sudo\s+apt\s+autoremove$',
    r'^sudo\s+apt\s+clean$',
    r'^sudo\s+apt\s+update\s+&&\s+sudo\s+apt\s+upgrade$', # Combined update/upgrade

    # systemctl and service commands
    r'^sudo\s+systemctl\s+(start|stop|restart|status|enable|disable|daemon-reload)\s+[a-zA-Z0-9_\-\.]+$', # Broader systemctl actions
    r'^sudo\s+service\s+[a-zA-Z0-9_\-]+\s+(start|stop|restart|status)$',

    # System power commands
    r'^sudo\s+reboot$',
    r'^sudo\s+shutdown\s+(-r\s+)?now$',

    # dpkg commands
    r'^sudo\s+dpkg\s+-i\s+[a-zA-Z0-9_/.\-]+\.deb$',

    # Specific tools like ClamAV (added based on common suggestions/user feedback)
    r'^sudo\s+freshclam$',
    r'^sudo\s+clamscan\s+.*$', # Allows clamscan with any arguments (e.g., -r, --bell, -i, /path)
    # If you have a specific command in mind, add the appropriate pattern
]

# --- 4. Main function to interact with Gemini ---
def ask_gemini_about_system(query):
    """
    Sends a query to Gemini including current system info as context.
    """
    # Collecting current system information
    disk_info = get_disk_usage()
    memory_info = get_memory_usage()
    processes_info = get_running_processes()
    network_info = get_network_interfaces()
    uptime_info = get_system_uptime()

    # Structuring the information for Gemini (Prompt)
    system_context = f"""
    You are an AI assistant helping the user manage the Kali Linux system.
    Current system info:
    {disk_info}
    {memory_info}
    {processes_info}
    {network_info}
    {uptime_info}

    Based on the above information and my question, please respond.
    If my question is about system status (disk, memory, processes, network or uptime),
    answer using only the above info.
    If you suggest a Linux command, output it on a separate line prefixed with `COMMAND:`.
    Example:
    COMMAND: ls -l /home/user
    COMMAND: systemctl status apache2
    COMMAND: ping google.com

    My question: {query}
    """

    try:
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            err_msg = (
                "Error: Gemini API key not found.\n"
                "Please set the GEMINI_API_KEY environment variable."
            )
            logging.error(err_msg)
            return err_msg
        client = genai.Client(
            api_key=api_key,
        )
        model = "gemini-2.5-flash-preview-05-20"
        contents = [
            types.Content(
                role="user",
                parts=[
                    types.Part.from_text(text=system_context),
                ],
            ),
        ]
        generate_content_config = types.GenerateContentConfig(
            response_mime_type="text/plain",
        )
        response_text = ""
        for chunk in client.models.generate_content_stream(
            model=model,
            contents=contents,
            config=generate_content_config,
        ):
            if hasattr(chunk, "text"):
                response_text += chunk.text
        return response_text
    except Exception as e:
        err_msg = str(e)
        if "Temporary failure in name resolution" in err_msg or "Failed to establish a new connection" in err_msg:
            user_msg = (
                "Error: Unable to connect to Gemini API.\n"
                "Please check your internet connection and try again."
            )
            logging.error(user_msg)
            return user_msg
        logging.error(f"Error communicating with Gemini: {e}")
        return f"Error communicating with Gemini: {e}"

def transform_apt_command(cmd):
    # Automatically add -y flag to apt commands if missing
    if cmd.startswith("sudo apt install") and "-y" not in cmd:
        cmd = cmd.replace("sudo apt install", "sudo apt install -y", 1)
    elif cmd.startswith("sudo apt upgrade") and "-y" not in cmd:
        cmd = cmd.replace("sudo apt upgrade", "sudo apt upgrade -y", 1)
    elif cmd.startswith("sudo apt autoremove") and "-y" not in cmd:
        cmd = cmd.replace("sudo apt autoremove", "sudo apt autoremove -y", 1)
    elif cmd.startswith("sudo apt purge") and "-y" not in cmd:
        cmd = cmd.replace("sudo apt purge", "sudo apt purge -y", 1)
    return cmd

# New PyQt5 based UI class
class MonitoringWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.cpu = 0
        self.ram = 0
        self.disk = 0
        self.gpu = None  # None means not available
        self.setMinimumHeight(90)
        self.setMaximumHeight(110)
        self.setStyleSheet("background: transparent;")

    def set_stats(self, cpu, ram, disk, gpu=None):
        self.cpu = cpu
        self.ram = ram
        self.disk = disk
        self.gpu = gpu
        self.update()

    def _usage_color(self, percent):
        # Smooth gradient: green (0%) -> yellow (50%) -> orange (75%) -> red (100%)
        if percent < 50:
            r = int(90 + (255-90)*(percent/50))
            g = 255
            b = 90 - int(90*(percent/50))
            return QColor(r, g, b)
        elif percent < 75:
            r = 255
            g = int(255 - (95 * ((percent-50)/25)))
            b = 80
            return QColor(r, g, b)
        else:
            r = 255
            g = int(160 - (80 * ((percent-75)/25)))
            b = 80 - int(80 * ((percent-75)/25))
            return QColor(r, max(g,0), max(b,0))

    def _draw_gloss(self, painter, x, y, w, h):
        # Draw a glossy highlight on top of the bar
        grad = QColor(255, 255, 255, 60)
        painter.setBrush(grad)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(x, y, w, h//2, 10, 10)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        font = QFont('Segoe UI', 12, QFont.Weight.Bold)
        painter.setFont(font)
        stats = [("CPU", self.cpu), ("RAM", self.ram), ("Disk", self.disk)]
        if self.gpu is not None:
            stats.append(("GPU", self.gpu))
        n = len(stats)
        bar_w = max(120, (self.width() - 40 - (n-1)*30) // n)
        bar_h = 36
        spacing = 30
        y = 22
        for i, (label, percent) in enumerate(stats):
            x = 20 + i * (bar_w + spacing)
            # Draw shadow
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(30, 30, 50, 110))
            painter.drawRoundedRect(x+3, y+6, bar_w, bar_h, 12, 12)
            # Draw background bar
            painter.setBrush(QColor(35, 32, 66, 230))
            painter.setPen(QColor(90, 90, 120, 180))
            painter.drawRoundedRect(x, y, bar_w, bar_h, 12, 12)
            # Draw usage bar with gradient color
            usage_color = self._usage_color(percent)
            grad = QLinearGradient(x, y, x+bar_w, y+bar_h)
            grad.setColorAt(0, usage_color.lighter(120))
            grad.setColorAt(1, usage_color.darker(120))
            painter.setBrush(grad)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawRoundedRect(x, y, int(bar_w * percent / 100), bar_h, 12, 12)
            # Glossy highlight
            self._draw_gloss(painter, x, y, int(bar_w * percent / 100), bar_h)
            # Draw border
            painter.setPen(QColor(120, 255, 255, 90))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRoundedRect(x, y, bar_w, bar_h, 12, 12)
            # Draw text (label and percent)
            painter.setPen(QColor(230, 255, 255))
            painter.setFont(QFont('Segoe UI', 11, QFont.Weight.Bold))
            painter.drawText(x+14, y+bar_h-12, f"{label}: {percent:.0f}%")
            # Draw animated circle indicator at the end of the bar
            circle_x = x + int(bar_w * percent / 100)
            circle_y = y + bar_h//2
            painter.setBrush(usage_color.darker(130))
            painter.setPen(QColor(80, 80, 80, 120))
            painter.drawEllipse(circle_x-8, circle_y-8, 16, 16)
            painter.setBrush(QColor(255,255,255,60))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(circle_x-4, circle_y-4, 8, 8)
        # Draw a subtle bottom line for separation
        painter.setPen(QColor(120, 255, 255, 60))
        painter.drawLine(10, y+bar_h+10, self.width()-10, y+bar_h+10)
        painter.end()

    def sizeHint(self):
        return QSize(600, 90)

class GeminiSysAdminUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Gemini Sys Admin Assistant")
        self.resize(900, 700)
        self.setStyleSheet("""
            QWidget {
                background-color: #18122B;
                color: #E6E6E6;
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 15px;
            }
            QLabel#TitleLabel {
                color: #A3FFD6;
                font-size: 22px;
                font-weight: bold;
            }
            QLabel#SubTitleLabel {
                color: #FFD6E0;
                font-size: 15px;
            }
            QTextEdit, QLineEdit {
                border-radius: 10px;
                border: 1px solid #393053;
                background-color: #232042;
                color: #F2F2F2;
                padding: 8px;
            }
            QPushButton {
                background-color: #635985;
                color: #F2F2F2;
                border-radius: 8px;
                padding: 8px 18px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #A3FFD6;
                color: #232042;
            }
        """)
        self.input_history = []
        self.history_index = -1
        self.cmd_history = []
        self.history_index = -1
        self.active_threads = []
        self.loading_dialog = None  # Track loading dialog
        load_user_trusted_commands()
        self.init_ui()  
        self.append_output("--- Gemini Sys Admin Assistant ---", "system")
        self.append_output("This is an experimental tool. Run system commands at your own risk.", "system")
        self.append_output("Type 'exit' to quit.", "system")
        self.append_output("Type 'system status' to view complete system info.", "system")
        # Setup monitoring updates every second
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_monitoring)
        self.timer.start(1000)

    def init_ui(self):
        layout = QVBoxLayout()
        # Title area remains unchanged
        title = QLabel("Welcome to Gemini Sys Admin")
        title.setObjectName("TitleLabel")
        layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignHCenter)
        subtitle = QLabel("We are made for this. @Python.")
        subtitle.setObjectName("SubTitleLabel")
        layout.addWidget(subtitle, alignment=Qt.AlignmentFlag.AlignHCenter)
        # Monitoring widget remains above the tabs
        self.monitoring_widget = MonitoringWidget(self)
        layout.addWidget(self.monitoring_widget)
        
        # Create a QTabWidget for separate Chat and Log views
        self.tab_widget = QTabWidget()
        # Chat area: reusing output_area as chat widget
        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)
        self.chat_area.setStyleSheet("""
            background-color:#232042; 
            color:#F2F2F2; 
            border-radius: 12px;
            border: 1px solid #635985;
        """)
        # Log area: new text edit for log output
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setStyleSheet("""
            background-color:#1E1E2D; 
            color:#A3FFD6; 
            border-radius: 12px;
            border: 1px solid #635985;
        """)
        # Add tabs to the tab widget
        self.tab_widget.addTab(self.chat_area, "Chat")
        self.tab_widget.addTab(self.log_area, "Logs")
        layout.addWidget(self.tab_widget, stretch=1)
        
        # Main input area remains in a separate layout
        input_layout = QHBoxLayout()
        self.command_input = QLineEdit()
        self.command_input.installEventFilter(self)
        self.send_button = QPushButton("send")
        self.clear_button = QPushButton("clear output")
        input_layout.addWidget(self.command_input)
        input_layout.addWidget(self.send_button)
        input_layout.addWidget(self.clear_button)
        layout.addLayout(input_layout)
        self.setLayout(layout)
        # Connect buttons to their functions
        self.send_button.clicked.connect(self.on_send)
        self.clear_button.clicked.connect(self.clear_output)
        self.command_input.returnPressed.connect(self.on_send)

    def update_monitoring(self):
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
        gpu_percent = None
        if GPUtil:
            try:
                gpus = GPUtil.getGPUs()
                if gpus:
                    gpu_percent = gpus[0].load * 100
            except Exception:
                gpu_percent = None
        self.monitoring_widget.set_stats(cpu, ram, disk, gpu_percent)

    def append_output(self, text, tag=None):
        # Append chat messages to chat_area instead of the previous output_area
        color_map = {
            "user": "#44AAFF",
            "gemini": "#A3FFD6",
            "system": "#FFD6E0",
            "command": "#FF8888"
        }
        color = color_map.get(tag, "#F2F2F2")
        self.chat_area.append(f'<span style="color:{color}; font-weight:bold;">{text}</span>')
        
    # Optionally, add a method to update the log_area (e.g., reading from log file)
    def update_log_area(self):
        try:
            with open("gemini_sys_assistant.log", "r", encoding="utf-8") as f:
                log_content = f.read()
            self.log_area.setPlainText(log_content)
        except Exception as e:
            self.log_area.setPlainText(f"Error reading log file: {e}")
            
    # --- 4. Main function to interact with Gemini ---
    def ask_gemini_about_system(self, query):
        """
        Sends a query to Gemini including current system info as context.
        """
        # Collecting current system information
        disk_info = get_disk_usage()
        memory_info = get_memory_usage()
        processes_info = get_running_processes()
        network_info = get_network_interfaces()
        uptime_info = get_system_uptime()

        # Structuring the information for Gemini (Prompt)
        system_context = f"""
        You are an AI assistant helping the user manage the Kali Linux system.
        Current system info:
        {disk_info}
        {memory_info}
        {processes_info}
        {network_info}
        {uptime_info}

        Based on the above information and my question, please respond.
        If my question is about system status (disk, memory, processes, network or uptime),
        answer using only the above info.
        If you suggest a Linux command, output it on a separate line prefixed with `COMMAND:`.
        Example:
        COMMAND: ls -l /home/user
        COMMAND: systemctl status apache2
        COMMAND: ping google.com

        My question: {query}
        """

        try:
            api_key = os.environ.get("GEMINI_API_KEY")
            if not api_key:
                err_msg = (
                    "Error: Gemini API key not found.\n"
                    "Please set the GEMINI_API_KEY environment variable."
                )
                logging.error(err_msg)
                return err_msg
            client = genai.Client(
                api_key=api_key,
            )
            model = "gemini-2.5-flash-preview-05-20"
            contents = [
                types.Content(
                    role="user",
                    parts=[
                        types.Part.from_text(text=system_context),
                    ],
                ),
            ]
            generate_content_config = types.GenerateContentConfig(
                response_mime_type="text/plain",
            )
            response_text = ""
            for chunk in client.models.generate_content_stream(
                model=model,
                contents=contents,
                config=generate_content_config,
            ):
                if hasattr(chunk, "text"):
                    response_text += chunk.text
            return response_text
        except Exception as e:
            err_msg = str(e)
            if "Temporary failure in name resolution" in err_msg or "Failed to establish a new connection" in err_msg:
                user_msg = (
                    "Error: Unable to connect to Gemini API.\n"
                    "Please check your internet connection and try again."
                )
                logging.error(user_msg)
                return user_msg
            logging.error(f"Error communicating with Gemini: {e}")
            return f"Error communicating with Gemini: {e}"

    def transform_apt_command(cmd):
        # Automatically add -y flag to apt commands if missing
        if cmd.startswith("sudo apt install") and "-y" not in cmd:
            cmd = cmd.replace("sudo apt install", "sudo apt install -y", 1)
        elif cmd.startswith("sudo apt upgrade") and "-y" not in cmd:
            cmd = cmd.replace("sudo apt upgrade", "sudo apt upgrade -y", 1)
        elif cmd.startswith("sudo apt autoremove") and "-y" not in cmd:
            cmd = cmd.replace("sudo apt autoremove", "sudo apt autoremove -y", 1)
        elif cmd.startswith("sudo apt purge") and "-y" not in cmd:
            cmd = cmd.replace("sudo apt purge", "sudo apt purge -y", 1)
        return cmd

    # New PyQt5 based UI class
    class MonitoringWidget(QWidget):
        def __init__(self, parent=None):
            super().__init__(parent)
            self.cpu = 0
            self.ram = 0
            self.disk = 0
            self.gpu = None  # None means not available
            self.setMinimumHeight(90)
            self.setMaximumHeight(110)
            self.setStyleSheet("background: transparent;")

        def set_stats(self, cpu, ram, disk, gpu=None):
            self.cpu = cpu
            self.ram = ram
            self.disk = disk
            self.gpu = gpu
            self.update()

        def _usage_color(self, percent):
            # Smooth gradient: green (0%) -> yellow (50%) -> orange (75%) -> red (100%)
            if percent < 50:
                r = int(90 + (255-90)*(percent/50))
                g = 255
                b = 90 - int(90*(percent/50))
                return QColor(r, g, b)
            elif percent < 75:
                r = 255
                g = int(255 - (95 * ((percent-50)/25)))
                b = 80
                return QColor(r, g, b)
            else:
                r = 255
                g = int(160 - (80 * ((percent-75)/25)))
                b = 80 - int(80 * ((percent-75)/25))
                return QColor(r, max(g,0), max(b,0))

        def _draw_gloss(self, painter, x, y, w, h):
            # Draw a glossy highlight on top of the bar
            grad = QColor(255, 255, 255, 60)
            painter.setBrush(grad)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawRoundedRect(x, y, w, h//2, 10, 10)

        def paintEvent(self, event):
            painter = QPainter(self)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            font = QFont('Segoe UI', 12, QFont.Weight.Bold)
            painter.setFont(font)
            stats = [("CPU", self.cpu), ("RAM", self.ram), ("Disk", self.disk)]
            if self.gpu is not None:
                stats.append(("GPU", self.gpu))
            n = len(stats)
            bar_w = max(120, (self.width() - 40 - (n-1)*30) // n)
            bar_h = 36
            spacing = 30
            y = 22
            for i, (label, percent) in enumerate(stats):
                x = 20 + i * (bar_w + spacing)
                # Draw shadow
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(QColor(30, 30, 50, 110))
                painter.drawRoundedRect(x+3, y+6, bar_w, bar_h, 12, 12)
                # Draw background bar
                painter.setBrush(QColor(35, 32, 66, 230))
                painter.setPen(QColor(90, 90, 120, 180))
                painter.drawRoundedRect(x, y, bar_w, bar_h, 12, 12)
                # Draw usage bar with gradient color
                usage_color = self._usage_color(percent)
                grad = QLinearGradient(x, y, x+bar_w, y+bar_h)
                grad.setColorAt(0, usage_color.lighter(120))
                grad.setColorAt(1, usage_color.darker(120))
                painter.setBrush(grad)
                painter.setPen(Qt.PenStyle.NoPen)
                painter.drawRoundedRect(x, y, int(bar_w * percent / 100), bar_h, 12, 12)
                # Glossy highlight
                self._draw_gloss(painter, x, y, int(bar_w * percent / 100), bar_h)
                # Draw border
                painter.setPen(QColor(120, 255, 255, 90))
                painter.setBrush(Qt.BrushStyle.NoBrush)
                painter.drawRoundedRect(x, y, bar_w, bar_h, 12, 12)
                # Draw text (label and percent)
                painter.setPen(QColor(230, 255, 255))
                painter.setFont(QFont('Segoe UI', 11, QFont.Weight.Bold))
                painter.drawText(x+14, y+bar_h-12, f"{label}: {percent:.0f}%")
                # Draw animated circle indicator at the end of the bar
                circle_x = x + int(bar_w * percent / 100)
                circle_y = y + bar_h//2
                painter.setBrush(usage_color.darker(130))
                painter.setPen(QColor(80, 80, 80, 120))
                painter.drawEllipse(circle_x-8, circle_y-8, 16, 16)
                painter.setBrush(QColor(255,255,255,60))
                painter.setPen(Qt.PenStyle.NoPen)
                painter.drawEllipse(circle_x-4, circle_y-4, 8, 8)
            # Draw a subtle bottom line for separation
            painter.setPen(QColor(120, 255, 255, 60))
            painter.drawLine(10, y+bar_h+10, self.width()-10, y+bar_h+10)
            painter.end()

        def sizeHint(self):
            return QSize(600, 90)

    def on_send(self):
        user_input = self.command_input.text().strip()
        if not user_input:
            return
        self.append_output(f"You: {user_input}", "user")
        # save input to history
        self.input_history.append(user_input)
        if not self.cmd_history or (self.cmd_history and self.cmd_history[-1] != user_input):
            self.cmd_history.append(user_input)
        self.history_index = -1
        self.command_input.clear()
        if user_input.lower() == 'exit':
            QApplication.quit()
            return
        elif user_input.lower() == 'system status':
            disk_info = get_disk_usage()
            memory_info = get_memory_usage()
            processes_info = get_running_processes()
            network_info = get_network_interfaces()
            uptime_info = get_system_uptime()
            sys_status = (
                "\n--- Current System Status ---\n"
                + disk_info + "\n" + "-"*30 + "\n"
                + memory_info + "\n" + "-"*30 + "\n"
                + processes_info + "\n" + "-"*30 + "\n"
                + network_info + "\n" + "-"*30 + "\n"
                + uptime_info + "\n" + "-"*30 + "\n"
            )
            self.append_output(sys_status, "system")
            return
        gemini_response = ask_gemini_about_system(user_input)
        self.append_output(f"Gemini: {gemini_response}", "gemini")
        suggested_commands = re.findall(r'^COMMAND:\s*(.*)$', gemini_response, re.MULTILINE)
        if suggested_commands:
            for cmd in suggested_commands:
                self.execute_safe_command_gui(cmd)

    def is_command_safe(self, command, whitelist):
        for pattern in whitelist:
            if re.match(pattern, command):
                return True
        return False

    def show_confirm_popup(self, title, message, on_confirm):
        reply = QMessageBox.question(self, title, message, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        on_confirm(reply == QMessageBox.StandardButton.Yes)

    def show_input_popup(self, title, message, default_text, on_submit):
        text, ok = QInputDialog.getText(self, title, message, text=default_text)
        if ok:
            on_submit(text)
        else:
            on_submit(None)

    def show_progress_popup(self, title, message):
        # if was a loading dialog, close it
        if self.loading_dialog is not None:
            self.loading_dialog.close()
            self.loading_dialog = None
        progress = QProgressDialog(message, None, 0, 0, self)
        progress.setWindowTitle(title)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setAutoClose(False)
        progress.setMinimumDuration(0)
        progress.setCancelButton(None)
        progress.setLabelText(message)
        progress.setStyleSheet("""
            QProgressDialog {
                background-color: #232042;
                color: #F2F2F2;
                border-radius: 12px;
                border: 1px solid #635985;
            }
            QProgressBar {
                border: 1px solid #A3FFD6;
                border-radius: 8px;
                background: #18122B;
                height: 18px;
            }
            QProgressBar::chunk {
                background-color: #A3FFD6;
                width: 20px;
            }
        """)
        progress.setValue(0)
        progress.show()
        self.loading_dialog = progress
        return progress

    # New QThread worker for executing commands asynchronously:
    class CommandWorker(QThread):
        finished_signal = pyqtSignal(str, str)  # stdout, stderr

        def __init__(self, command):
            super().__init__()
            self.command = command

        def run(self):
            try:
                proc = subprocess.run(self.command, shell=True, check=True, capture_output=True, text=True)
                stdout, stderr = proc.stdout, proc.stderr
            except subprocess.CalledProcessError as e:
                stdout, stderr = e.stdout, e.stderr
            except Exception as e:
                stdout, stderr = "", str(e)
            self.finished_signal.emit(stdout, stderr)

    def _run_command_gui(self, command):
        # بررسی Whitelist/Trusted قبلش (همون‌جایی که بود)
        if not self.is_command_safe(command, SAFE_COMMANDS_WHITELIST) and not self.is_command_safe(command, user_trusted_commands):
            self.show_confirm_popup("Confirm Command Execution", f"Command '{command}' is not recognized as safe.\nDo you really want to execute it?", lambda confirmed: self._execute_command_if_confirmed(command, confirmed))
            return

        # اگر دستور مربوط به sudo است و گزینه -S ندارد، از کاربر رمز روت می‌گیرد.
        if "sudo" in command and "-S" not in command:
            from PyQt6.QtWidgets import QInputDialog, QLineEdit
            password, ok = QInputDialog.getText(self, "Root Password", "Enter root password:", QLineEdit.EchoMode.Password)
            if not ok or not password:
                self.append_output("Password not provided. Command cancelled.", "command")
                self.command_input.setEnabled(True)
                self.send_button.setEnabled(True)
                self.clear_button.setEnabled(True)
                return
            command = command.replace("sudo", "sudo -S", 1)
            command = "echo " + shlex.quote(password) + " | " + command

        # Add apt non-interactive flag if needed
        command = transform_apt_command(command)
        
        # تشخیص اجرای برنامه گرافیکی و عدم نمایش لودینگ برای آن
        gui_apps = ["google-chrome", "firefox", "chromium", "code", "gedit", "vlc", "nautilus", "dolphin"]
        is_gui = False
        for app in gui_apps:
            if command.strip().startswith(app) or f" {app}" in command:
                is_gui = True
                break

        if is_gui:
            try:
                subprocess.Popen(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.append_output(f"Launched: {command}", "command")
            except Exception as e:
                self.append_output(f"خطا:\n{str(e)}", "command")
            self.command_input.setEnabled(True)
            self.send_button.setEnabled(True)
            self.clear_button.setEnabled(True)
            return

        # غیرفعال کردن ورودی تا پایان اجرا
        self.command_input.setEnabled(False)
        self.send_button.setEnabled(False)
        self.clear_button.setEnabled(False)

        progress = self.show_progress_popup("لطفاً صبر کن", "در حال اجرای فرمان…")
        worker = self.CommandWorker(transform_apt_command(command))
        self.active_threads.append(worker)  # Track the running thread
        worker.finished_signal.connect(lambda out, err: self.on_command_finished_wrapper(worker, out, err, progress))
        worker.start()

    def on_command_finished_wrapper(self, worker, stdout, stderr, progress):
        if worker in self.active_threads:
            self.active_threads.remove(worker)
        self.on_command_finished(stdout, stderr, progress)

    def on_command_finished(self, stdout, stderr, progress):
        if progress:
            progress.close()
        if stdout:
            self.output_area.append(stdout)
        if stderr:
            self.output_area.append(f"خطا:\n{stderr}")
        self.command_input.setEnabled(True)
        self.send_button.setEnabled(True)
        self.clear_button.setEnabled(True)

    def execute_safe_command_gui(self, command):
        # بررسی Whitelist/Trusted قبلش (همون‌جایی که بود)
        if not self.is_command_safe(command, SAFE_COMMANDS_WHITELIST) and not self.is_command_safe(command, user_trusted_commands):
            self.show_confirm_popup("Confirm Command Execution", f"Command '{command}' is not recognized as safe.\nDo you really want to execute it?", lambda confirmed: self._execute_command_if_confirmed(command, confirmed))
            return

        # اگر دستور مربوط به sudo است و گزینه -S ندارد، از کاربر رمز روت می‌گیرد.
        if "sudo" in command and "-S" not in command:
            from PyQt6.QtWidgets import QInputDialog, QLineEdit
            password, ok = QInputDialog.getText(self, "Root Password", "Enter root password:", QLineEdit.EchoMode.Password)
            if not ok or not password:
                self.append_output("Password not provided. Command cancelled.", "command")
                self.command_input.setEnabled(True)
                self.send_button.setEnabled(True)
                self.clear_button.setEnabled(True)
                return
            command = command.replace("sudo", "sudo -S", 1)
            command = "echo " + shlex.quote(password) + " | " + command

        # Add apt non-interactive flag if needed
        command = transform_apt_command(command)
        
        # تشخیص اجرای برنامه گرافیکی و عدم نمایش لودینگ برای آن
        gui_apps = ["google-chrome", "firefox", "chromium", "code", "gedit", "vlc", "nautilus", "dolphin"]
        is_gui = False
        for app in gui_apps:
            if command.strip().startswith(app) or f" {app}" in command:
                is_gui = True
                break

        if is_gui:
            try:
                subprocess.Popen(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.append_output(f"Launched: {command}", "command")
            except Exception as e:
                self.append_output(f"خطا:\n{str(e)}", "command")
            self.command_input.setEnabled(True)
            self.send_button.setEnabled(True)
            self.clear_button.setEnabled(True)
            return

        # Use the new QThread worker instead of manual thread and timer
        self._run_command_gui(command)

    def clear_output(self):
        """Clear the output QTextEdit completely."""
        self.output_area.clear()
    
    def eventFilter(self, source, event):
        if source == self.command_input and event.type() == QEvent.Type.KeyPress:
            key = event.key()
            if key == Qt.Key.Key_Up:  # changed from Qt.Key_Up to Qt.Key.Key_Up
                if self.cmd_history and self.history_index + 1 < len(self.cmd_history):
                    self.history_index += 1
                    self.command_input.setText(self.cmd_history[-1 - self.history_index])
                return True
            elif key == Qt.Key.Key_Down:  # changed from Qt.Key_Down to Qt.Key.Key_Down
                if self.cmd_history and self.history_index > 0:
                    self.history_index -= 1
                    self.command_input.setText(self.cmd_history[-1 - self.history_index])
                elif self.cmd_history and self.history_index == 0:
                    self.history_index = -1
                    self.command_input.clear()
                return True
        return super().eventFilter(source, event)
    
    def closeEvent(self, event):
        """
            when the window is closed, wait for all threads to finish
        """
        # Wait for all active threads to finish
        for thread in self.active_threads:
            thread.wait(3000)  # wait up to 3000 ms for each thread
        if self.loading_dialog:
            self.loading_dialog.close()
            self.loading_dialog = None
        event.accept()

    def _execute_command_if_confirmed(self, command, confirmed):
        if confirmed:
            self._run_command_gui(command)
        else:
            self.append_output("Command execution canceled.", "command")
    
# New main function using PyQt5
def main():
    app = QApplication(sys.argv)
    window = GeminiSysAdminUI()
    window.show()
    sys.exit(app.exec())
    
if __name__ == "__main__":
    main()
