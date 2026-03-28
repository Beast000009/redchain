"""
RedChain i18n — Internationalization support for reports and CLI output.
Supports: en, es, fr, de, ja, zh, ar, pt, ko, hi
"""

SUPPORTED_LANGUAGES = {
    "en": "English",
    "es": "Español",
    "fr": "Français",
    "de": "Deutsch",
    "ja": "日本語",
    "zh": "中文",
    "ar": "العربية",
    "pt": "Português",
    "ko": "한국어",
    "hi": "हिन्दी",
}

# LLM prompt instructions per language
REPORT_LANGUAGE_INSTRUCTIONS = {
    "en": "Write the entire report in English.",
    "es": "Escribe todo el informe en español.",
    "fr": "Rédigez l'intégralité du rapport en français.",
    "de": "Schreiben Sie den gesamten Bericht auf Deutsch.",
    "ja": "レポート全体を日本語で作成してください。",
    "zh": "请用中文撰写整个报告。",
    "ar": "اكتب التقرير بالكامل باللغة العربية.",
    "pt": "Escreva todo o relatório em português.",
    "ko": "전체 보고서를 한국어로 작성하세요.",
    "hi": "पूरी रिपोर्ट हिंदी में लिखें।",
}

# CLI message strings
MESSAGES = {
    "en": {
        "scan_start": "Starting RedChain against",
        "scan_complete": "Workflow completed!",
        "target_not_scope": "Target NOT in scope (or scope.json missing). Continue anyway?",
        "missing_tools": "Some required tools are missing.",
        "update_available": "Update available for external tools",
        "checking_deps": "Checking Required Dependencies...",
        "all_deps_met": "All required dependencies met!",
        "no_target": "Must provide --target or --file",
        "skipping_target": "Skipping target.",
        "generating_report": "Generating AI narrative and report...",
        "osint_running": "Running OSINT on",
        "scan_running": "Running vulnerability scans...",
        "phase_complete": "Finished phase:",
        "errors_found": "Pipeline completed with errors in:",
    },
    "es": {
        "scan_start": "Iniciando RedChain contra",
        "scan_complete": "¡Flujo de trabajo completado!",
        "target_not_scope": "Objetivo NO está en el alcance. ¿Continuar de todos modos?",
        "missing_tools": "Faltan algunas herramientas requeridas.",
        "update_available": "Actualización disponible para herramientas externas",
        "checking_deps": "Verificando dependencias requeridas...",
        "all_deps_met": "¡Todas las dependencias cumplidas!",
        "no_target": "Debe proporcionar --target o --file",
        "skipping_target": "Omitiendo objetivo.",
        "generating_report": "Generando narrativa IA e informe...",
        "osint_running": "Ejecutando OSINT en",
        "scan_running": "Ejecutando escaneos de vulnerabilidades...",
        "phase_complete": "Fase completada:",
        "errors_found": "Pipeline completado con errores en:",
    },
    "fr": {
        "scan_start": "Démarrage de RedChain contre",
        "scan_complete": "Flux de travail terminé !",
        "target_not_scope": "Cible PAS dans le périmètre. Continuer quand même ?",
        "missing_tools": "Certains outils requis sont manquants.",
        "update_available": "Mise à jour disponible pour les outils externes",
        "checking_deps": "Vérification des dépendances requises...",
        "all_deps_met": "Toutes les dépendances sont satisfaites !",
        "no_target": "Vous devez fournir --target ou --file",
        "skipping_target": "Cible ignorée.",
        "generating_report": "Génération du narratif IA et du rapport...",
        "osint_running": "Exécution de l'OSINT sur",
        "scan_running": "Exécution des analyses de vulnérabilités...",
        "phase_complete": "Phase terminée :",
        "errors_found": "Pipeline terminé avec des erreurs dans :",
    },
}

# Fallback to English for unsupported languages
def get_message(key: str, lang: str = "en") -> str:
    """Get a localized message string, falling back to English."""
    lang_messages = MESSAGES.get(lang, MESSAGES["en"])
    return lang_messages.get(key, MESSAGES["en"].get(key, key))


def get_report_language_instruction(lang: str = "en") -> str:
    """Get the LLM instruction for report language."""
    return REPORT_LANGUAGE_INSTRUCTIONS.get(lang, REPORT_LANGUAGE_INSTRUCTIONS["en"])
