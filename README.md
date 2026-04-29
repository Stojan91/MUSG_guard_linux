<img width="800" height="507" alt="musggdash-ezgif com-video-to-gif-converter" src="https://github.com/user-attachments/assets/18eb1e6e-9d8d-4585-9480-b94ba499e473" />



# MUSG Guard Linux

Lokalny guard dla Linuxa z GUI, skanowaniem plików, kontrolą procesów i połączeń, integracją z ClamAV oraz obsługą modeli ONNX Runtime do dalszego rozwoju modułów analizy. [web:111][web:107]

## Wymagania

- Linux z aktywną sesją graficzną.
- Python 3.10 lub nowszy.
- Git.
- Pakiety systemowe potrzebne do ClamAV i środowiska graficznego. [web:281][web:295]

## Instalacja projektu

W komendach niżej wpisz własną nazwę użytkownika zamiast `YOUR_USER`. Dzięki temu README nie ujawnia żadnych prywatnych danych środowiska. [web:291]

```bash
cd /home/YOUR_USER
git clone https://github.com/Stojan91/MUSG_guard_linux.git
cd /home/YOUR_USER/MUSG_guard_linux
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
```

## Pakiety systemowe

Zainstaluj zależności systemowe potrzebne do działania guarda i ClamAV:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git clamav clamav-daemon clamav-freshclam
```

Jeżeli `clamav-daemon` nie działa, aplikacja może użyć `clamscan` jako fallback zamiast `clamdscan`, bo skan przez `clamdscan` wymaga aktywnego socketu demona. [web:281][web:251]

## Instalacja bibliotek Python

Po aktywacji virtualenv zainstaluj biblioteki wymagane przez projekt i ONNX Runtime:

```bash
cd /home/YOUR_USER/MUSG_guard_linux
source .venv/bin/activate
pip install onnxruntime
```

Oficjalna dokumentacja ONNX Runtime podaje `pip install onnxruntime` jako pakiet CPU dla Pythona, a `onnxruntime-gpu` jako osobny wariant GPU, którego nie należy instalować równolegle z pakietem CPU w tym samym środowisku. [web:107][web:111]

## Wdrożenie ONNX

Utwórz katalog na modele i umieść w nim własny plik `.onnx`:

```bash
mkdir -p /home/YOUR_USER/MUSG_guard_linux/models
```

Przykładowy test importu ONNX Runtime:

```bash
cd /home/YOUR_USER/MUSG_guard_linux
source .venv/bin/activate
python -c "import onnxruntime as ort; print(ort.get_available_providers())"
```

Jeżeli chcesz potem użyć modelu w kodzie, standardowy start wygląda tak:

```python
import onnxruntime as ort

session = ort.InferenceSession("/home/YOUR_USER/MUSG_guard_linux/models/model.onnx")
print(session.get_inputs())
print(session.get_outputs())
```

ONNX Runtime udostępnia dla Pythona `InferenceSession`, która służy do ładowania modelu i wykonywania inferencji. [web:107]

## Aktualizacja sygnatur ClamAV

Przed pierwszym użyciem zaktualizuj sygnatury:

```bash
sudo systemctl stop clamav-freshclam 2>/dev/null || true
sudo freshclam
sudo systemctl enable --now clamav-daemon
```

Jeżeli daemon nie uruchomi się poprawnie, guard może nadal działać przez `clamscan`, ale wydajność będzie zwykle słabsza niż przy aktywnym `clamd`. [web:281][web:251]

## Uruchomienie ręczne

```bash
cd /home/YOUR_USER/MUSG_guard_linux
source .venv/bin/activate
python main.py
```

## Autostart guarda

Najbezpieczniej uruchamiać GUI po zalogowaniu użytkownika przez usługę `systemd --user`, powiązaną z `graphical-session.target`. [web:295][web:292]

Utwórz skrypt startowy:

```bash
mkdir -p /home/YOUR_USER/MUSG_guard_linux/scripts
nano /home/YOUR_USER/MUSG_guard_linux/scripts/start_guard.sh
```

Wklej:

```bash
#!/usr/bin/env bash
cd /home/YOUR_USER/MUSG_guard_linux
source /home/YOUR_USER/MUSG_guard_linux/.venv/bin/activate
python /home/YOUR_USER/MUSG_guard_linux/main.py
```

Nadaj uprawnienia:

```bash
chmod +x /home/YOUR_USER/MUSG_guard_linux/scripts/start_guard.sh
```

Utwórz usługę użytkownika:

```bash
mkdir -p /home/YOUR_USER/.config/systemd/user
nano /home/YOUR_USER/.config/systemd/user/musg-guard.service
```

Wklej:

```ini
[Unit]
Description=MUSG Guard GUI
After=graphical-session.target
PartOf=graphical-session.target

[Service]
Type=simple
WorkingDirectory=/home/YOUR_USER/MUSG_guard_linux
ExecStart=/home/YOUR_USER/MUSG_guard_linux/scripts/start_guard.sh
Restart=on-failure
RestartSec=5

[Install]
WantedBy=graphical-session.target
```

Włącz usługę:

```bash
systemctl --user daemon-reload
systemctl --user enable musg-guard.service
systemctl --user start musg-guard.service
```

`graphical-session.target` jest używany do uruchamiania usług użytkownika powiązanych z sesją graficzną. [web:295][web:292]

## Sprawdzenie autostartu

```bash
systemctl --user status musg-guard.service
journalctl --user -u musg-guard.service -n 50 --no-pager
```

## Aktualizacja projektu

```bash
cd /home/YOUR_USER/MUSG_guard_linux
git pull
source .venv/bin/activate
pip install --upgrade pip
pip install onnxruntime
```

## Uwagi

- W README celowo użyto `YOUR_USER` zamiast prawdziwej nazwy konta.
- Nie wpisuj do repo prywatnych ścieżek, nazw hosta ani lokalnych danych środowiska.
- Jeżeli projekt ma używać ONNX do wykrywania, model `.onnx` powinien być przechowywany lokalnie w katalogu `models/`.
