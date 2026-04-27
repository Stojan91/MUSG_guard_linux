<img width="800" height="507" alt="musggdash-ezgif com-video-to-gif-converter" src="https://github.com/user-attachments/assets/18eb1e6e-9d8d-4585-9480-b94ba499e473" />

Musg Guard
Musg Guard to lokalny agent ochrony hosta z graficznym interfejsem w Pythonie. Aplikacja monitoruje katalog Downloads, analizuje uruchomione procesy i sprawdza aktywne połączenia sieciowe, a następnie zapisuje alerty i logi lokalnie w katalogu data/.

Projekt jest przeznaczony do uruchamiania na Linuxie z GUI. Aktualna wersja korzysta z tkinter do interfejsu oraz z lokalnych mechanizmów systemowych takich jak ps i ss do zbierania informacji o procesach i połączeniach.

Funkcje programu
Skanowanie katalogu Downloads pod kątem ryzykownych rozszerzeń plików.

Wykrywanie procesów po słowach kluczowych, na przykład hydra, sqlmap, netcat lub msfconsole.

Wykrywanie połączeń sieciowych na wskazanych portach, na przykład 23, 4444, 5555, 6667 i 1337.

Panel GUI z zakładkami Dashboard, Alerty, Logi i Ustawienia.

Lokalny zapis zdarzeń do data/guard-events.jsonl i alertów do data/alerts.json.

Edycja konfiguracji z poziomu aplikacji przez config.json.

Struktura projektu
text
musg_guard_complete/
├── agent.py
├── main.py
├── config.json
├── README.md
├── data/
│   ├── alerts.json
│   └── guard-events.jsonl
└── ui/
    ├── __init__.py
    ├── alerts.py
    ├── dashboard.py
    ├── logs.py
    └── settings.py
Wymagania
Przed instalacją upewnij się, że masz:

Python 3.10 lub nowszy.

Pakiet python3-tk, jeśli tkinter nie jest dostępny domyślnie.

System Linux z aktywnym środowiskiem graficznym.

Na Debianie, Ubuntu lub Kali możesz doinstalować brakujące pakiety poleceniem:

bash
sudo apt update
sudo apt install -y python3 python3-venv python3-tk
tkinter jest biblioteką GUI używaną bezpośrednio przez main.py, a skanowanie procesów i połączeń opiera się w kodzie na ps i ss, więc projekt zakłada środowisko linuksowe.

Instalacja krok po kroku
Sklonuj repozytorium:

bash
git clone https://github.com/Stojan91/MUSG_guard_linux.git
cd MUSG_guard_linux
Utwórz środowisko wirtualne:

bash
python3 -m venv .venv
Aktywuj środowisko:

bash
source .venv/bin/activate
Jeśli chcesz, zaktualizuj pip:

bash
python -m pip install --upgrade pip
Uruchom aplikację:

bash
python main.py
W obecnej wersji projektu nie ma obowiązkowych zewnętrznych bibliotek z pip, ponieważ GUI używa tkinter, a logika ochrony korzysta głównie z modułów standardowych Pythona i narzędzi systemowych.

Pierwsze uruchomienie
Po starcie programu:

Otwórz zakładkę Ustawienia.

Sprawdź pole downloads_dir i ustaw poprawną ścieżkę do katalogu pobrań.

Ustaw scan_interval_seconds, jeśli chcesz zmienić częstotliwość skanowania.

Zapisz konfigurację.

Wróć do Dashboard i kliknij Run.

Domyślnie konfiguracja zawiera listę ryzykownych rozszerzeń, słów kluczowych procesów i podejrzanych portów, które agent sprawdza w każdej pętli skanowania.

Konfiguracja
Plik config.json pozwala zmieniać podstawowe parametry działania:

scan_interval_seconds – interwał kolejnych skanów.

downloads_dir – katalog obserwowany przez moduł plików.

suspicious_extensions – lista rozszerzeń uznawanych za ryzykowne.

suspicious_process_keywords – słowa kluczowe używane przy analizie procesów.

suspicious_connection_ports – lista portów używana przy analizie połączeń.

user_protection – przełączniki aktywnych modułów ochrony.

Przykład:

json
{
  "scan_interval_seconds": 20,
  "downloads_dir": "/home/stojak/Downloads",
  "suspicious_extensions": [".exe", ".scr", ".bat", ".cmd", ".ps1", ".jar", ".apk", ".msi", ".zip"],
  "suspicious_process_keywords": ["nc", "ncat", "netcat", "hydra", "john", "sqlmap", "msfconsole"],
  "suspicious_connection_ports": [23, 4444, 5555, 6667, 1337],
  "user_protection": {
    "download_guard": true,
    "process_guard": true,
    "connection_guard": true,
    "clipboard_secret_warning": true
  }
}
Jak działa program
Po kliknięciu Run aplikacja uruchamia lokalny wątek agenta i przechodzi w stan ACTIVE. Agent wykonuje pełny skan, a następnie powtarza go cyklicznie zgodnie z wartością scan_interval_seconds.

Skan plików sprawdza katalog Downloads i porównuje rozszerzenia znalezionych plików z listą suspicious_extensions. Jeśli wykryje dopasowanie, zapisuje alert o podejrzanym pliku.

Skan procesów pobiera listę aktywnych procesów przez polecenie ps -eo pid,comm,args i szuka zadanych słów kluczowych w nazwach oraz argumentach procesu. Dopasowania zwiększają licznik wykryć i trafiają do alertów.

Skan połączeń korzysta w Linuxie z ss -tunp i zgłasza wpisy zawierające porty z listy suspicious_connection_ports. Takie zdarzenia są zapisywane jako alerty sieciowe.

Logi i alerty
Program zapisuje dane lokalnie:

data/guard-events.jsonl – szczegółowy dziennik zdarzeń.

data/alerts.json – lista alertów wyświetlana w GUI.

Jeśli chcesz wyczyścić historię testów, możesz zamknąć program i usunąć zawartość tych plików ręcznie.

Uruchamianie przy starcie systemu
Masz dwie praktyczne metody: autostart sesji graficznej przez plik .desktop albo usługę systemd --user. Dla aplikacji z GUI najprostszy jest plik .desktop, a dla samego agenta bez ręcznego klikania wygodny bywa systemd --user uruchamiany po zalogowaniu.

Opcja 1: autostart GUI przez .desktop
Utwórz katalog autostartu, jeśli jeszcze nie istnieje:

bash
mkdir -p ~/.config/autostart
Potem utwórz plik:

bash
nano ~/.config/autostart/musg-guard.desktop
Wklej:

text
[Desktop Entry]
Type=Application
Name=Musg Guard
Comment=Local host protection agent
Exec=/usr/bin/env bash -lc 'cd /home/stojak/MUSG_guard_linux && python3 main.py'
Path=/home/stojak/MUSG_guard_linux
Terminal=false
X-GNOME-Autostart-enabled=true
Categories=Utility;Security;
Jeśli używasz środowiska wirtualnego, lepiej uruchamiać właściwego Pythona z .venv:

text
[Desktop Entry]
Type=Application
Name=Musg Guard
Comment=Local host protection agent
Exec=/home/stojak/MUSG_guard_linux/.venv/bin/python /home/stojak/MUSG_guard_linux/main.py
Path=/home/stojak/MUSG_guard_linux
Terminal=false
X-GNOME-Autostart-enabled=true
Categories=Utility;Security;
Po ponownym zalogowaniu aplikacja powinna uruchomić się razem z sesją graficzną.
