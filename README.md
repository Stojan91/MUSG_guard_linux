<img width="800" height="507" alt="musggdash-ezgif com-video-to-gif-converter" src="https://github.com/user-attachments/assets/18eb1e6e-9d8d-4585-9480-b94ba499e473" />

# Musg Guard

Musg Guard to lokalna aplikacja ochronna dla Linuxa z prostym GUI w Pythonie.
Program monitoruje podstawowe zdarzenia systemowe i zapisuje alerty lokalnie.

## Instalacja

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-tk
cd ~/musg_guard_complete
python3 -m venv .venv
source .venv/bin/activate
python main.py
```

## Uruchomienie

```bash
cd ~/musg_guard_complete
source .venv/bin/activate
python main.py
```

## Konfiguracja

Podstawowe ustawienia znajdziesz w pliku `config.json`.
Po zmianach uruchom program ponownie.

## Autostart

### Opcja 1: autostart GUI

Utwórz plik `~/.config/autostart/musg-guard.desktop`:

```ini
[Desktop Entry]
Type=Application
Name=Musg Guard
Exec=/home/stojak/musg_guard_complete/.venv/bin/python /home/stojak/musg_guard_complete/main.py
Path=/home/stojak/musg_guard_complete
Terminal=false
X-GNOME-Autostart-enabled=true
```

Aktywacja:

```bash
systemctl --user daemon-reload
systemctl --user enable musg-guard.service
systemctl --user start musg-guard.service
```


