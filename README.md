# Nessus - HackMyVM Writeup

![Nessus Icon](Nessus.png)

## Übersicht

*   **VM:** Nessus
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Nessus)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 27. Juni 2025
*   **Original-Writeup:** https://alientec1908.github.io/Nessus_HackMyVM_Easy/
*   **Autor:** Ben C.

---

**Disclaimer:**

Dieser Writeup dient ausschließlich zu Bildungszwecken und dokumentiert Techniken, die in einer kontrollierten Testumgebung (HackTheBox/HackMyVM) angewendet wurden. Die Anwendung dieser Techniken auf Systeme, für die keine ausdrückliche Genehmigung vorliegt, ist illegal und ethisch nicht vertretbar. Der Autor und der Ersteller dieses README übernehmen keine Verantwortung für jeglichen Missbrauch der hier beschriebenen Informationen.

---

## Zusammenfassung

Die Box "Nessus" erforderte eine gründliche Windows-Enumeration. Nach der Identifizierung des Systems und offener Dienste via Nmap und enum4linux, insbesondere SMB und ein Nessus-Webinterface, konnte über eine anonym zugängliche SMB-Freigabe auf sensible Dokumente zugegriffen werden. Die Analyse dieser Dokumente lieferte einen potenziellen Benutzernamen ('Jose') und eine Passwortliste in Form von PDF-Metadaten.

Der Benutzername 'Jose' konnte für einen Brute-Force-Angriff gegen das Nessus-Webinterface auf Port 8834 genutzt werden, was zur Entdeckung der Anmeldedaten 'jose:tequiero' führte. Der Login in Nessus offenbarte eine weitere, kritischere Informationslecks in den Proxy-Einstellungen, wo die Anmeldedaten eines anderen Benutzers ('nesus') im Base64-Format abgefangen werden konnten.

Die mitgeschnittenen Anmeldedaten 'nesus:Z#JuXH$ph-;v@,X&mV)' ermöglichten den Zugang zum System über WinRM, jedoch war das Passwort abgelaufen. Nach einer Passwortänderung konnte die WinRM-Sitzung erfolgreich hergestellt werden. Als Benutzer 'nesus' wurde das System erkundet und user.txt gefunden.

Die finale Privilegieneskalation zum Administrator wurde durch Ausnutzung einer DLL-Hijacking-Schwachstelle in der Nessus-Installation erreicht. Eine bösartige DLL wurde erstellt, hochgeladen und durch einen Systemneustart geladen, wodurch ein neuer Administrator-Benutzer ('hacker') erstellt wurde, der den Zugriff auf root.txt ermöglichte.

## Technische Details

*   **Betriebssystem:** Microsoft Windows Server 2022
*   **Offene Ports:**
    *   `135/tcp`: MSRPC
    *   `139/tcp`: NetBIOS SSN
    *   `445/tcp`: Microsoft-DS (SMB)
    *   `5985/tcp`: HTTP (WinRM)
    *   `8834/tcp`: SSL/HTTP (Nessus Web Interface)
    *   `47001/tcp`: HTTP
    *   Diverse RPC-Ports (49664-49671)

## Enumeration

1.  **ARP-Scan:** Identifizierung der Ziel-IP (192.168.2.65).
2.  **Enum4linux:** Bestätigung eines Windows-Systems mit WORKGROUP und NetBIOS-Namen NESSUS.
3.  **Nmap Scan:** Detaillierte Identifizierung offener Ports, Dienste und des Betriebssystems (Windows Server 2022). Port 8834 wurde als Nessus-Webinterface identifiziert, das HTTPS erfordert. WinRM (Port 5985) war ebenfalls offen.
4.  **SMB Enumeration:** Anonyme SMB-Freigaben wurden mit `smbclient -L` aufgelistet. Die Freigabe `Documents` war anonym lesbar.
5.  **Analyse der Dokumente:** Dateien wie `desktop.ini` und PDF-Dokumente wurden von der `Documents`-Freigabe heruntergeladen. Exiftool auf den PDFs zeigte "Jose" als Autor, was einen potenziellen Benutzernamen lieferte.

## Initialer Zugriff (Nessus Webinterface)

1.  **Nessus Login Brute-Force:** Basierend auf dem Benutzernamen 'Jose' und der Vermutung, dass ein einfaches Passwort verwendet wurde, wurde ein Brute-Force-Angriff gegen den Nessus-Login-Endpunkt (`/session`) auf Port 8834 durchgeführt.
2.  **Credential Fund:** Mittels ffuf und der rockyou.txt Wordlist wurde das Passwort `tequiero` für den Benutzer `jose` gefunden. Dies ermöglichte den Login in das Nessus-Webinterface.

## Lateral Movement (Nessus -> WinRM als nesus)

1.  **Nessus Informationslecks:** Nach erfolgreichem Login in Nessus wurden die Einstellungen erkundet. Auf der Proxy-Server-Konfigurationsseite wurden die Anmeldedaten eines Proxy-Benutzers (`nesus`) im Base64-Format gefunden, nachdem die Authentifizierungsmethode auf "Basic" umgestellt und der Traffic mitgeschnitten wurde.
2.  **Credential Decoding:** Die Base64-kodierten Anmeldedaten (`bmVzdXM6WiNKdVhIJHphLTt2QCxYJm1WKQ==`) wurden dekodiert und ergaben das Benutzer/Passwort-Paar `nesus:Z#JuXH$ph-;v@,X&mV)`.
3.  **WinRM Zugang:** Es wurde versucht, sich via WinRM mit diesen Anmeldedaten anzumelden (`evil-winrm -u nesus -p 'Z#JuXH$ph-;v@,X&mV)'`). Dies schlug zunächst fehl, da das Passwort abgelaufen war.
4.  **Passwortänderung:** Das Passwort für den Benutzer `nesus` wurde geändert (im Writeup-Protokoll nicht explizit gezeigt, aber impliziert durch das neue, funktionierende Passwort). Das neue Passwort war `Test88888$$$`.
5.  **WinRM Shell:** Mit dem neuen Passwort (`nesus:Test88888$$$`) konnte erfolgreich eine WinRM-Sitzung etabliert werden, was eine Shell als Benutzer `nesus` ermöglichte. Die user.txt konnte auf dem Desktop dieses Benutzers (`C:\Users\nesus\Desktop\user.txt`) gefunden werden.

## Privilegieneskalation (nesus -> Administrator)

1.  **DLL Hijacking Analyse:** Das Nessus-Verzeichnis (`C:\Program Files\Tenable\Nessus`) wurde untersucht. Die Existenz von DLL-Dateien, die beim Start des Nessus-Dienstes geladen werden könnten, wurde vermutet.
2.  **Bösartige DLL Erstellung:** Eine einfache C-DLL (`hacker.c`) wurde geschrieben und mit dem MinGW-Compiler (`x86_64-w64-mingw32-gcc`) kompiliert. Diese DLL führt beim Laden die Befehle `net user hacker hacker /add` und `net localgroup administrators hacker /add` aus, um einen neuen lokalen Administrator-Benutzer zu erstellen.
3.  **DLL Austausch:** Die Original-DLL `legacy.dll` im Nessus-Verzeichnis wurde gesichert und die bösartige DLL (`legacy.dll`) unter demselben Namen hochgeladen (`evil-winrm upload`).
4.  **Trigger durch Neustart:** Durch einen Neustart des Systems (`restart-computer -force`) wurde der Nessus-Dienst mit Root-Rechten gestartet, der die manipulierte `legacy.dll` lud. Dies führte zur Ausführung des Payloads in der DLL und zur Erstellung des Administrator-Benutzers `hacker`.
5.  **Zugang als Administrator:** Es konnte sich erfolgreich via WinRM als der neu erstellte Benutzer `hacker` mit dem Passwort `hacker` angemeldet werden.
6.  **root.txt:** Mit Administrator-Rechten konnte auf den Desktop des Administrators zugegriffen und die `root.txt` (`C:\Users\Administrator\Desktop\root.txt`) gelesen werden.

## Flags

*   **user.txt:** `72113f41d43e88eb5d67f732668bc3d1` (Gefunden unter `C:\Users\nesus\Desktop\user.txt`)
*   **root.txt:** `b5fc5a4ebfc20cc18220a814e1aee0aa` (Gefunden unter `C:\Users\Administrator\Desktop\root.txt`)

---
