"""Message catalogue for alerts the daemon sends: English, German, Spanish.

The GUI has its own Qt translations; the daemon has no locale of its own
(it runs as root under systemd), so its language comes from the `language`
setting.
"""
from __future__ import annotations

LANGS = ("en", "de", "es")

MESSAGES = {
    "infected_title": {"en": "Threat found", "de": "Bedrohung gefunden", "es": "Amenaza detectada"},
    "suspicious_title": {"en": "Suspicious file", "de": "Verdächtige Datei", "es": "Archivo sospechoso"},
    "warning_title": {"en": "Warning", "de": "Warnung", "es": "Advertencia"},
    "critical_title": {"en": "Threat in a system file", "de": "Bedrohung in einer Systemdatei",
                       "es": "Amenaza en un archivo del sistema"},
    "quarantined": {"en": "{sig}\n{path}\nMoved to quarantine.",
                    "de": "{sig}\n{path}\nIn Quarantäne verschoben.",
                    "es": "{sig}\n{path}\nMovido a cuarentena."},
    "reported": {"en": "{sig}\n{path}\nLeft in place (not quarantined).",
                 "de": "{sig}\n{path}\nAn Ort und Stelle belassen (nicht in Quarantäne).",
                 "es": "{sig}\n{path}\nSe dejó en su sitio (sin cuarentena)."},
    "held": {"en": "{sig}\n{path}\nUnchanged for {days} days, so it was left in place. Decide in Lguard: trust it or remove it.",
             "de": "{sig}\n{path}\nSeit {days} Tagen unverändert, daher an Ort und Stelle belassen. In Lguard entscheiden: vertrauen oder entfernen.",
             "es": "{sig}\n{path}\nSin cambios desde hace {days} días, por eso se dejó en su sitio. Decida en Lguard: confiar o eliminar."},
    "held_title": {"en": "Possible threat in an old file", "de": "Mögliche Bedrohung in einer alten Datei",
                   "es": "Posible amenaza en un archivo antiguo"},
    "signed_ok": {"en": "Publisher signature intact{who} – this is often a false alarm.",
                  "de": "Herausgebersignatur intakt{who} – das ist oft ein Fehlalarm.",
                  "es": "Firma del editor intacta{who}: a menudo es una falsa alarma."},
    "signed_broken": {"en": "The file was changed after its publisher signed it.",
                      "de": "Die Datei wurde nach der Signatur des Herausgebers verändert.",
                      "es": "El archivo fue modificado después de que el editor lo firmara."},
    "quarantine_failed": {"en": "{sig}\n{path}\nQuarantine FAILED: {err}",
                          "de": "{sig}\n{path}\nQuarantäne FEHLGESCHLAGEN: {err}",
                          "es": "{sig}\n{path}\nLa cuarentena FALLÓ: {err}"},
    "ransom_title": {"en": "RANSOMWARE ALARM", "de": "RANSOMWARE-ALARM", "es": "ALARMA DE RANSOMWARE"},
    "ransom_body": {"en": "{n} files look encrypted in {mins} min (last: {path}). Process: {proc}.\n{frozen}",
                    "de": "{n} Dateien wirken in {mins} Min. verschlüsselt (zuletzt: {path}). Prozess: {proc}.\n{frozen}",
                    "es": "{n} archivos parecen cifrados en {mins} min (último: {path}). Proceso: {proc}.\n{frozen}"},
    "rewrite_body": {"en": "Process {proc} rewrote {n} existing files in {mins} min.\n{frozen}",
                     "de": "Prozess {proc} hat {n} vorhandene Dateien in {mins} Min. überschrieben.\n{frozen}",
                     "es": "El proceso {proc} reescribió {n} archivos existentes en {mins} min.\n{frozen}"},
    "combo_body": {"en": "Process {proc} removed {gone} documents and wrote {new} unreadable files in {mins} min.\n{frozen}",
                   "de": "Prozess {proc} hat in {mins} Min. {gone} Dokumente entfernt und {new} unlesbare Dateien geschrieben.\n{frozen}",
                   "es": "El proceso {proc} eliminó {gone} documentos y escribió {new} archivos ilegibles en {mins} min.\n{frozen}"},
    "stopped": {"en": "The program was suspended (pid {pids}). Let it continue: lguard resume-process",
                "de": "Das Programm wurde angehalten (PID {pids}). Fortsetzen: lguard resume-process",
                "es": "El programa fue suspendido (pid {pids}). Para continuar: lguard resume-process"},
    "paused_title": {"en": "Scanning is paused", "de": "Scan ist pausiert", "es": "El análisis está en pausa"},
    "paused_body": {"en": "Paused from the app until {until}.", "de": "In der App pausiert bis {until}.",
                    "es": "En pausa desde la aplicación hasta {until}."},
    "frozen": {"en": "Backups/sync FROZEN. Undo: lguard unfreeze",
               "de": "Backup/Sync EINGEFROREN. Aufheben: lguard unfreeze",
               "es": "Copias/sincronización CONGELADAS. Deshacer: lguard unfreeze"},
    "not_frozen": {"en": "No freeze commands configured.", "de": "Kein Einfrieren konfiguriert.",
                   "es": "No hay congelación configurada."},
    "tamper_title": {"en": "TAMPERING DETECTED", "de": "MANIPULATION ERKANNT", "es": "MANIPULACIÓN DETECTADA"},
    "tamper_body": {"en": "{what}: {why}. The affected files are being rescanned.",
                    "de": "{what}: {why}. Die betroffenen Dateien werden erneut gescannt.",
                    "es": "{what}: {why}. Los archivos afectados se están volviendo a analizar."},
    "integrity_title": {"en": "System changes", "de": "Systemänderungen", "es": "Cambios en el sistema"},
    "weekly_title": {"en": "Weekly report", "de": "Wochenbericht", "es": "Informe semanal"},
    "weekly_body": {"en": "Scanned {scanned} files ({cached} unchanged), {findings} findings. Signatures {db}.",
                    "de": "{scanned} Dateien gescannt ({cached} unverändert), {findings} Funde. Signaturen {db}.",
                    "es": "{scanned} archivos analizados ({cached} sin cambios), {findings} hallazgos. Firmas {db}."},
    "clamd_down_title": {"en": "Scanner not running", "de": "Scanner läuft nicht", "es": "El escáner no funciona"},
    "clamd_down_body": {"en": "The scan engine does not answer; files are queued.",
                        "de": "Die Scan-Engine antwortet nicht; Dateien warten in der Warteschlange.",
                        "es": "El motor de análisis no responde; los archivos esperan en cola."},
    "media_clean_title": {"en": "{category}: download checked – clean", "de": "{category}: Download geprüft – sauber",
                          "es": "{category}: descarga comprobada – limpia"},
}

_lang = "en"


def set_language(lang: str):
    global _lang
    _lang = lang if lang in LANGS else "en"


def t(key: str, **kw) -> str:
    entry = MESSAGES.get(key, {})
    text = entry.get(_lang) or entry.get("en") or key
    return text.format(**kw) if kw else text
