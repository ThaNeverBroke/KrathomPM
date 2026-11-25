<p align="center">
  <img src="logo.svg" width="110" alt="KratomPM logo">
</p>

<h1 align="center">KratomPM</h1>

<p align="center">
  <b>A PM2-style process manager with a web dashboard, in one Python file.</b><br>
  Run your Python and Node.js projects on a phone, a Raspberry Pi, a VPS or a PC.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Node.js-supported-339933?style=for-the-badge&logo=nodedotjs&logoColor=white" alt="Node.js">
  <img src="https://img.shields.io/badge/Dependencies-none-10b981?style=for-the-badge" alt="No dependencies">
  <img src="https://img.shields.io/badge/License-MIT-f59e0b?style=for-the-badge" alt="MIT">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Termux-Android-000000?style=flat-square&logo=termux&logoColor=white" alt="Termux">
  <img src="https://img.shields.io/badge/Raspberry%20Pi-supported-C51A4A?style=flat-square&logo=raspberrypi&logoColor=white" alt="Raspberry Pi">
  <img src="https://img.shields.io/badge/Linux-VPS-FCC624?style=flat-square&logo=linux&logoColor=black" alt="Linux">
  <img src="https://img.shields.io/badge/Windows-PC-0078D6?style=flat-square" alt="Windows">
  <img src="https://img.shields.io/badge/Cloudflare-Tunnel-F38020?style=flat-square&logo=cloudflare&logoColor=white" alt="Cloudflare Tunnel">
  <img src="https://img.shields.io/badge/Telegram-notify-26A5E4?style=flat-square&logo=telegram&logoColor=white" alt="Telegram">
</p>

---

## ✨ Why KratomPM

Process managers are powerful but often hard to set up. KratomPM is made to be simple:

```
python main.py
```

Open the dashboard, add your project, press Start. No `npm install`, no config files, no extra packages.

## 🚀 Features

| | |
|---|---|
| 🖥️ **Web dashboard** | Start, stop and restart projects. Works great on a phone screen. |
| 📜 **Live logs and stats** | Output, CPU and RAM per project, and internet ping. |
| 📦 **Auto install** | Installs `requirements.txt` / `package.json`. If a project crashes with a missing module, it installs it and starts again. |
| 🗂️ **Packages page** | Global pip and npm packages. Loads instantly from a background cache. |
| 📤 **Upload from any device** | Add a project from a ZIP or a `.py` / `.js` file on your phone or PC. |
| 🔁 **Replace files remotely** | Edit code on another device and upload it over the same project folder. |
| 🌍 **Public link** | Cloudflare Tunnel link with a QR code. It renews itself when it dies. |
| 🔔 **Telegram** | Your public link is sent to your Telegram every time it changes. |
| ♻️ **Resume** | Projects that were running start again when KratomPM starts. |
| 🔒 **Login** | Password protected, dark mode, memory limit per project. |

## 📥 Install

Choose your system below. You only need Python. Node.js is optional (for `.js` projects) and `cloudflared` is optional (for the public link).


### 📱 Termux (Android)


```bash
pkg update && pkg install -y python git cloudflared
# optional, for Node.js projects: pkg install -y nodejs
git clone https://github.com/ThaNeverBroke/KrathomPM.git
cd KrathomPM
python main.py
```

To use folders on your phone storage, run `termux-setup-storage` once.



### 🪟 Windows (PowerShell)


```powershell
winget install -e --id Python.Python.3.12
winget install -e --id Git.Git
winget install -e --id Cloudflare.cloudflared
# optional, for Node.js projects: winget install -e --id OpenJS.NodeJS.LTS
```

Close PowerShell, open it again, then:

```powershell
git clone https://github.com/ThaNeverBroke/KrathomPM.git
cd KrathomPM
python main.py
```



### 🐧 Linux and Raspberry Pi (Debian / Ubuntu)


```bash
sudo apt update && sudo apt install -y python3 python3-pip git curl
# optional, for Node.js projects: sudo apt install -y nodejs npm
# cloudflared (use cloudflared-linux-arm64 on Raspberry Pi):
curl -L -o cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
sudo install -m 755 cloudflared /usr/local/bin/cloudflared
git clone https://github.com/ThaNeverBroke/KrathomPM.git
cd KrathomPM
python3 main.py
```

On newer Debian and Raspberry Pi OS, pip refuses to install packages system wide. Run `export PIP_BREAK_SYSTEM_PACKAGES=1` before starting KratomPM so it can install what your projects need.


## 🏁 First start

1. Open `http://127.0.0.1:8000` (it opens by itself on a desktop).
2. Log in with the default password `123` and **change it in Settings right away**.
3. After a few seconds the public link appears on the Dashboard (if `cloudflared` is installed).
4. Click **Add Project**, choose a folder or upload a ZIP, pick the entry file, Save, Start.

Settings and projects are saved in `kratompm_data.json` next to the script. Uploaded projects go into the `projects/` folder.

## ⚙️ Start automatically on boot


### Windows


Press `Win + R`, run `shell:startup`, and create `kratompm-start.bat` in that folder:

```bat
@echo off
cd /d "C:\path\to\KrathomPM"
python main.py
```



### Linux / Raspberry Pi (systemd)


Create `/etc/systemd/system/kratompm.service` (replace `pi` with your user name):

```ini
[Unit]
Description=KratomPM
After=network-online.target
Wants=network-online.target

[Service]
User=pi
WorkingDirectory=/home/pi/KrathomPM
ExecStart=/usr/bin/python3 /home/pi/KrathomPM/main.py
Environment=PYTHONUNBUFFERED=1
Environment=PIP_BREAK_SYSTEM_PACKAGES=1
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Then run:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now kratompm
```



### Termux


Install the Termux:Boot app and put a script in `~/.termux/boot/` that runs `cd ~/KrathomPM && python main.py`.


## 🔔 Telegram notification

Open **Settings, Telegram** and enter your bot token (from @BotFather) and your chat ID. Send your bot a message first so it is allowed to write to you. The public link is sent every time it opens or changes.

## 🔐 Security, please read

- KratomPM can **run any code** on the machine it runs on. Treat the dashboard like a remote shell.
- Change the default password `123` immediately.
- The public Cloudflare link is open to the whole internet. Anyone who has it can reach the login page. Use a strong password and do not share the link.
- By default KratomPM listens only on `127.0.0.1`. Only change the host to `0.0.0.0` behind a reverse proxy with HTTPS.
- Never commit or share `kratompm_data.json`. It holds your password hash and Telegram token.

## 📝 Good to know

- A project that crashes is not restarted automatically. Only missing modules are installed, then it starts once more.
- Tested on Linux. It is used daily on Windows and Termux by the author, but your system may differ, so please open an issue if something breaks.

## 📄 License

MIT, see [LICENSE](LICENSE).

---

<p align="center">Made in Cambodia 🇰🇭 by <a href="https://github.com/ThaNeverBroke">@ThaNeverBroke</a></p>
