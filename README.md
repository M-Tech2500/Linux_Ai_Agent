# Gemini Sys Admin Assistant

A desktop assistant for Linux system administration powered by Google Gemini AI and PyQt6.

**Developed by [M-Tech2500](https://github.com/)**

---![Screenshot_20250602_110529](https://github.com/user-attachments/assets/d6461e46-9c1f-4b86-8b53-1049200a5c44)


## Features

- System status monitoring (CPU, RAM, Disk, Network, Uptime)
- Natural language queries to Gemini AI with system context
- Safe command execution with user confirmation and whitelisting
- Trusted commands management
- Modern PyQt6 GUI

## Requirements

- Python 3.10+ (tested on  Python 3.11.6)
- PyQt6
- psutil
- GPUtil (optional, for GPU monitoring)
- google-genai (Gemini API)
- Linux OS Debian/Ubuntu (tested on Kali Linux)

## Installation

```bash
pip install -r requirements.txt
```

## Environment Setup

Set your Gemini API key as an environment variable:

```bash
export GEMINI_API_KEY=your_gemini_api_key_here
```

## Usage

```bash
python gemini_sys_admin/ddd.py
```

## Security

- Only whitelisted or user-trusted commands can be executed.
- Sudo commands require password input.
- Review and edit `SAFE_COMMANDS_WHITELIST` in the code for your needs.

## License

See [LICENSE](LICENSE).

## Disclaimer

This tool is experimental. Use at your own risk.

---

© 2025 M-Tech

