# EDR-Bypass-Techniken & Referenz

Dieses Dokument beschreibt die im MostShittyEDR-Lab verwendeten Bypass-Techniken und ihre reale Relevanz.

## Ueberblick: Detektionsregeln und ihre Schwaechen

### Regel 1: Prozessname-Blacklist

**Technik:** Vergleich des Prozessnamens mit einer statischen Liste bekannter Tools.

**Schwaechen:**
- Case-Sensitive Vergleich (`==` statt `cmpIgnoreCase`)
- Nur exakte Dateinamen, keine Hashes oder Signaturen
- Statische Liste mit nur 12 Eintraegen
- Kein Pfad-Abgleich

**Bypass-Methoden:**
1. Umbenennung der Datei
2. Gross-/Kleinschreibung aendern
3. Tool nicht in der Liste verwenden

---

### Regel 2: Kommandozeilen-Keywords

**Technik:** Substring-Suche in der Kommandozeile nach verdaechtigen Begriffen.

**Schwaechen:**
- Keine Deobfuskierung (Carets, Env-Vars, Encoding)
- Nur ASCII-toLower (kein Unicode-Normalization)
- Einfacher String-Vergleich ohne Kontext

**Bypass-Methoden:**
1. Caret-Insertion (`who^ami`)
2. Umgebungsvariablen-Substitution (`%COMSPEC:~-7,1%`)
3. Base64-Encoding
4. String-Konkatenation

---

### Regel 3: Aufklaerungserkennung

**Technik:** Erkennung von Reconnaissance-Befehlen.

**Schwaeche:** Ergebnis wird mit `discard` verworfen - erkennt, aber blockiert nie.

**Bypass:** Nicht noetig - die Regel tut nichts.

---

### Regel 4: LSASS-Dump-Erkennung

**Technik:** Duale Bedingung: Toolname UND "lsass" Keyword muessen beide vorhanden sein.

**Schwaechen:**
- Umbenennung des Tools bricht die erste Bedingung
- Verwendung der PID statt des Namens bricht die zweite Bedingung
- Beide Bedingungen muessen gleichzeitig erfuellt sein

**Bypass-Methoden:**
1. Tool umbenennen (bricht Bedingung 1)
2. PID statt "lsass" verwenden (bricht Bedingung 2)
3. Beides kombinieren (bricht beide Bedingungen)

---

### Regel 5: PowerShell-Analyse

**Technik:** Prueft PowerShell-Flags wie `-encodedcommand`, `-noprofile`, `bypass`.

**Schwaeche:** Prueft nur Prozesse namens `powershell.exe` - `pwsh.exe` wird ignoriert.

**Bypass-Methoden:**
1. PowerShell 7 (`pwsh.exe`) verwenden
2. PowerShell Engine ueber .NET hosten
3. Flag-Abkuerzungen (`-EC` statt `-encodedcommand`)

---

### Regel 6: Hash-Erkennung

**Technik:** Vergleich von Datei-Hashes mit einer Malware-Datenbank.

**Schwaeche:** Datenbank ist leer UND Ergebnis wird mit `discard` verworfen.

**Bypass:** Nicht noetig - reine Sicherheits-Theatralik.

---

## Architektur-Schwaechen

### Polling-basiertes Monitoring

Das EDR pollt Prozesse mit `CreateToolhelp32Snapshot` in einem festen Intervall. Kurzlebige Prozesse zwischen zwei Polls sind unsichtbar.

**Gegenmaßnahme:** Kernel-Callbacks (`PsSetCreateProcessNotifyRoutineEx`) werden synchron bei Prozess-Erstellung aufgerufen.

### Kein Pre-Existing-Process-Scan

Alle Prozesse, die vor dem EDR-Start laufen, werden als "bekannt" markiert und nie analysiert.

### Nur 64-Bit PEB-Offsets

Die Kommandozeilen-Extraktion verwendet feste 64-Bit-Offsets. Fuer 32-Bit-Prozesse (WoW64) sind die Offsets falsch.

### ASCII-Only String-Handling

Unicode-Zeichen werden zu `?` konvertiert. Homoglyphen (visuell identische Zeichen mit unterschiedlichem Codepoint) brechen den Pattern-Matching.

### Keine DLL/Modul-Ueberwachung

DLL-Injection, Process Hollowing und Thread-Hijacking sind vollstaendig unsichtbar.

### Kein ETW-Integration

Keine Kernel-Level-Telemetrie. Kein ScriptBlock-Logging. Keine AMSI-Integration.

---

## Vergleich: MostShittyEDR vs. Echte EDR-Produkte

| Feature | MostShittyEDR | Echte EDR |
|---------|--------------|-----------|
| Prozess-Monitoring | Polling (Toolhelp32) | Kernel-Callbacks |
| Kommandozeile | PEB-Reading (User-Mode) | Kernel-Capture bei Erstellung |
| String-Matching | Substring, Case-Sensitive | Regex, YARA, ML |
| Deobfuskierung | Keine | Dynamische Analyse |
| Hash-Pruefung | Leere Datenbank | Cloud-basierte Threat Intelligence |
| Verhaltenserkennung | Keine | ML-basierte Anomalieerkennung |
| DLL-Monitoring | Keines | Kernel-Minifilter, ETW |
| Netzwerk | Keines | DNS, HTTP, TLS-Inspektion |
| Memory-Scanning | Keines | Periodische Memory-Scans |
| Privilege | User-Mode | SYSTEM / Kernel-Mode |
