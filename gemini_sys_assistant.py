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
    QLineEdit, QPushButton, QMessageBox, QInputDialog, QProgressDialog
)
from PyQt6.QtCore import QTimer, Qt, QEvent
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

# New PyQt5 based UI class
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
        # Title
        title = QLabel("Welcome to Gemini Sys Admin")
        title.setObjectName("TitleLabel")
        layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignHCenter)
        subtitle = QLabel("We are made for this. @Python.")
        subtitle.setObjectName("SubTitleLabel")
        layout.addWidget(subtitle, alignment=Qt.AlignmentFlag.AlignHCenter)
        # Monitoring label at top
        self.monitoring_label = QLabel("Monitoring: CPU: 0% | RAM: 0%" + ("" if GPUtil is None else " | GPU: N/A") + " | Disk: 0%")
        self.monitoring_label.setStyleSheet("color: #A3FFD6; font-weight: bold;")
        layout.addWidget(self.monitoring_label)
        # Output log (read-only text edit)
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        self.output_area.setStyleSheet("""
            background-color:#232042; 
            color:#F2F2F2; 
            border-radius: 12px;
            border: 1px solid #635985;
        """)
        layout.addWidget(self.output_area, stretch=1)
        # main input area
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
        gpu_info = ""
        if GPUtil:
            try:
                gpus = GPUtil.getGPUs()
                if gpus:
                    gpu = gpus[0]
                    gpu_info = f" | GPU: {gpu.load * 100:.0f}%"
                else:
                    gpu_info = " | GPU: N/A"
            except Exception:
                gpu_info = " | GPU: N/A"
        self.monitoring_label.setText(f"Monitoring: CPU: {cpu}% | RAM: {ram}% | Disk: {disk}%{gpu_info}")

    def append_output(self, text, tag=None):
        # Tag color mapping
        color_map = {
            "user": "#44AAFF",
            "gemini": "#A3FFD6",
            "system": "#FFD6E0",
            "command": "#FF8888"
        }
        color = color_map.get(tag, "#F2F2F2")
        self.output_area.append(f'<span style="color:{color}; font-weight:bold;">{text}</span>')

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

    def execute_safe_command_gui(self, command):
        """
        Executes a command in a separate thread with a loading dialog.
        """
    
        if not self.is_command_safe(command, SAFE_COMMANDS_WHITELIST) and not self.is_command_safe(command, user_trusted_commands):
            self.show_confirm_popup("Confirm Command Execution", f"Command '{command}' is not recognized as safe.\nDo you really want to execute it?", lambda confirmed: self._execute_command_if_confirmed(command, confirmed))
            return

        # detect if command is a GUI application
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
            # enable input and buttons
            self.command_input.setEnabled(True)
            self.send_button.setEnabled(True)
            self.clear_button.setEnabled(True)
            return

        # disable input and buttons while running command
        self.command_input.setEnabled(False)
        self.send_button.setEnabled(False)
        self.clear_button.setEnabled(False)

        progress = self.show_progress_popup("please wait ", "executing command…")

        run_proc_result = [None, None]
        finished = [False]

        def run():
            try:
                proc = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                run_proc_result[0] = proc.stdout
                run_proc_result[1] = proc.stderr
            except subprocess.CalledProcessError as e:
                run_proc_result[0] = e.stdout
                run_proc_result[1] = e.stderr
            except Exception as e:
                run_proc_result[0] = ""
                run_proc_result[1] = str(e)
            finished[0] = True

        thread = threading.Thread(target=run)
        self.active_threads.append(thread)
        thread.start()

        def finish_loading():
            if finished[0]:
                if self.loading_dialog:
                    self.loading_dialog.close()
                    self.loading_dialog = None
                if run_proc_result[0]:
                    self.output_area.append(run_proc_result[0])
                if run_proc_result[1]:
                    self.output_area.append(f"خطا:\n{run_proc_result[1]}")
                if thread in self.active_threads:
                    self.active_threads.remove(thread)
                self.command_input.setEnabled(True)
                self.send_button.setEnabled(True)
                self.clear_button.setEnabled(True)
                timer.stop()

        timer = QTimer(self)
        timer.timeout.connect(finish_loading)
        timer.start(200)

    def _execute_command_if_confirmed(self, command, confirmed):
        """
        Called when a command not recognized as safe is confirmed by the user.
        If confirmed, execute the command without further safety checks;
        otherwise, cancel execution.
        """
        if confirmed:
            self._run_command_gui(command)
        else:
            self.append_output("Command execution canceled.", "command")

    def _run_command_gui(self, command):
        """
        Executes the given command by displaying a QProgressDialog until done.
        This method bypasses the safe checking (confirmation already handled).
        """
        # disable input and buttons while running command
        self.command_input.setEnabled(False)
        self.send_button.setEnabled(False)
        self.clear_button.setEnabled(False)
        progress = self.show_progress_popup("please wait", "executing command…")
        run_proc_result = [None, None]
        finished = [False]

        def run():
            try:
                proc = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                run_proc_result[0] = proc.stdout
                run_proc_result[1] = proc.stderr
            except subprocess.CalledProcessError as e:
                run_proc_result[0] = e.stdout
                run_proc_result[1] = e.stderr
            except Exception as e:
                run_proc_result[0] = ""
                run_proc_result[1] = str(e)
            finished[0] = True

        thread = threading.Thread(target=run)
        self.active_threads.append(thread)
        thread.start()

        def finish_loading():
            if finished[0]:
                if self.loading_dialog:
                    self.loading_dialog.close()
                    self.loading_dialog = None
                if run_proc_result[0]:
                    self.output_area.append(run_proc_result[0])
                if run_proc_result[1]:
                    self.output_area.append(f"Error:\n{run_proc_result[1]}")
                if thread in self.active_threads:
                    self.active_threads.remove(thread)
                self.command_input.setEnabled(True)
                self.send_button.setEnabled(True)
                self.clear_button.setEnabled(True)
                timer.stop()

        timer = QTimer(self)
        timer.timeout.connect(finish_loading)
        timer.start(200)

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
        if self.active_threads:
            msg = QMessageBox(self)
            msg.setWindowTitle("closing")
            msg.setText("please wait for all threads to finish")
            msg.setStandardButtons(QMessageBox.StandardButton.NoButton)
            msg.show()
            for thread in list(self.active_threads):
                thread.join(timeout=3)
            msg.close()
        if self.loading_dialog:
            self.loading_dialog.close()
            self.loading_dialog = None
        event.accept()
    
# New main function using PyQt5
def main():
    app = QApplication(sys.argv)
    window = GeminiSysAdminUI()
    window.show()
    sys.exit(app.exec())
    
if __name__ == "__main__":
    main()
