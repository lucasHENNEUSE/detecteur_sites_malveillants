import re
import urllib.parse
import streamlit as st
import time
import base64

# ── Config ────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="MalWatch — Détecteur de Sites Malveillants",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# ── Image ─────────────────────────────────────────────────────────────────────
def charger_image_base64(chemin):
    try:
        with open(chemin, "rb") as f:
            return base64.b64encode(f.read()).decode()
    except FileNotFoundError:
        return ""

img_b64 = charger_image_base64("lh.png")
img_html = (
    f'<img src="data:image/png;base64,{img_b64}" class="avatar">'
    if img_b64
    else '<div class="avatar-placeholder">🕵️</div>'
)

# ── CSS (statique, affiché une seule fois, jamais remplacé) ───────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html, body, [data-testid="stAppViewContainer"] {
    background: #0f1117 !important;
    color: #e2e8f0 !important;
    font-family: 'Inter', sans-serif !important;
}
[data-testid="stHeader"], #MainMenu, footer,
[data-testid="stToolbar"], [data-testid="stSidebar"] { display: none !important; }
.block-container { padding: 0 !important; max-width: 680px !important; margin: auto; }

/* Hero */
.hero {
    padding: 40px 36px 28px;
    display: flex; align-items: center; gap: 24px;
    border-bottom: 1px solid #1e2535; margin-bottom: 8px;
}
.avatar {
    width: 82px; height: 82px; border-radius: 50%;
    object-fit: cover; border: 2px solid #3b82f6;
    box-shadow: 0 0 18px #3b82f618; flex-shrink: 0;
}
.avatar-placeholder {
    width: 82px; height: 82px; border-radius: 50%;
    background: #1e2535; border: 2px solid #3b82f6;
    display: flex; align-items: center; justify-content: center;
    font-size: 28px; flex-shrink: 0;
}
.hero-text h1 { font-size: 26px; font-weight: 700; color: #f8fafc; }
.hero-text h1 span { color: #3b82f6; }
.hero-text p  { margin-top: 4px; font-size: 13px; color: #64748b; line-height: 1.5; }
.hero-badges  { display: flex; gap: 6px; margin-top: 10px; flex-wrap: wrap; }
.badge {
    font-size: 11px; padding: 2px 9px; border-radius: 20px;
    background: #1e2535; color: #94a3b8; border: 1px solid #2d3748;
    font-family: 'JetBrains Mono', monospace;
}
.badge.online { color: #22c55e; border-color: #22c55e30; background: #22c55e0d; }

/* Label URL */
.url-label {
    font-size: 11px; font-weight: 600; color: #475569;
    letter-spacing: 1.5px; text-transform: uppercase;
    padding: 20px 36px 6px;
}

/* Input + bouton */
[data-testid="stTextInput"] { padding: 0 36px !important; }
[data-testid="stTextInput"] input {
    background: #141824 !important; border: 1.5px solid #2d3748 !important;
    border-radius: 10px !important; color: #f1f5f9 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 14px !important; padding: 13px 15px !important;
}
[data-testid="stTextInput"] input:focus {
    border-color: #3b82f6 !important;
    box-shadow: 0 0 0 3px #3b82f610 !important;
}
[data-testid="stButton"] { padding: 0 36px !important; margin-top: 8px; }
[data-testid="stButton"] button {
    background: #3b82f6 !important; color: #fff !important;
    font-family: 'Inter', sans-serif !important; font-weight: 600 !important;
    font-size: 14px !important; border: none !important;
    border-radius: 10px !important; padding: 13px 24px !important;
    width: 100% !important; cursor: pointer !important;
}
[data-testid="stButton"] button:hover { background: #2563eb !important; }

/* Zone résultat — on utilise les composants natifs Streamlit, on les stylise */
[data-testid="stMetric"] { padding: 0 !important; }

/* Metric principale (score) */
div[data-testid="stMetricValue"] > div {
    font-size: 42px !important; font-weight: 800 !important;
    font-family: 'Inter', sans-serif !important;
}

/* Progress bar */
[data-testid="stProgressBar"] > div > div {
    border-radius: 6px !important;
}

/* Colonnes résultat */
.result-cols { padding: 0 36px; }

/* Carte alerte individuelle via st.info / st.warning / st.error */
[data-testid="stNotification"] {
    border-radius: 10px !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 14px !important;
}

/* Expander log */
[data-testid="stExpander"] { margin: 0 36px !important; }
[data-testid="stExpander"] summary {
    font-size: 12px !important; color: #475569 !important;
    font-family: 'JetBrains Mono', monospace !important;
}
.log-box {
    background: #0d1117; border: 1px solid #1e2535; border-radius: 8px;
    padding: 12px 16px; font-family: 'JetBrains Mono', monospace;
    font-size: 11.5px; line-height: 2; color: #475569;
}
.log-ok   { color: #22c55e; }
.log-err  { color: #ef4444; }
.log-warn { color: #f59e0b; }
.log-info { color: #3b82f6; }

/* Padding général zone résultat */
.zone-resultat { padding: 20px 36px 0; }

/* Footer */
.footer {
    padding: 22px 36px 32px; margin-top: 24px;
    border-top: 1px solid #1e2535;
    display: flex; justify-content: space-between;
}
.footer-l { font-size: 12px; color: #334155; }
.footer-l strong { color: #475569; }
.footer-r { font-size: 11px; color: #1e2535; font-family: 'JetBrains Mono', monospace; }
</style>
""", unsafe_allow_html=True)

# ── Données ───────────────────────────────────────────────────────────────────
LISTE_NOIRE = {
    "malware.com", "phishing-site.net", "evil-domain.ru",
    "free-virus.xyz", "steal-data.top", "hack-you.pw",
    "click-here-win.com", "update-virus.info",
}
MOTS_SUSPECTS = [
    "login", "secure", "account", "verify", "update", "banking",
    "paypal", "amazon", "free", "win", "prize", "urgent", "suspended",
    "confirm", "password", "wallet", "crypto", "invoice", "alert",
    "click", "download",
]
EXTENSIONS_RISQUEES = [".xyz", ".top", ".pw", ".ru", ".tk", ".ml", ".ga", ".cf"]

EXPLICATIONS = {
    "LISTE_NOIRE":   ("☠️",  "Site dangereux répertorié",      "Ce domaine est dans notre base de menaces connues — virus, arnaques ou vols de données."),
    "SANS_TLS":      ("🔓",  "Connexion non sécurisée (HTTP)",  "Le site n'utilise pas HTTPS. Vos données peuvent être interceptées."),
    "EXT_RISQUEE":   ("⚠️",  "Extension de domaine risquée",   "Les extensions .xyz, .top, .ru etc. sont massivement utilisées pour des arnaques."),
    "IP_DIRECTE":    ("🖥️",  "Adresse IP brute",                "L'URL pointe sur une adresse IP — les sites légitimes ont toujours un vrai nom de domaine."),
    "URL_LONGUE":    ("📏",  "URL anormalement longue",         "Les liens très longs cachent souvent la vraie destination derrière des paramètres trompeurs."),
    "SOUS_DOMAINES": ("🔗",  "Trop de sous-domaines",           "L'URL empile des sous-domaines pour imiter un site officiel."),
    "CHARS_ENCODES": ("🔀",  "Caractères suspects dans l'URL",  "Des symboles comme % ou @ masquent la vraie adresse de destination."),
    "MOTS_PHISHING": ("🎣",  "Mots-clés d'hameçonnage",         "L'URL contient des mots typiques des tentatives de phishing."),
}

# ── Analyse ───────────────────────────────────────────────────────────────────
def analyser_url(url):
    rapport = {"url": url, "danger": False, "score": 0, "details": []}
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        parsed  = urllib.parse.urlparse(url)
        domaine = parsed.netloc.lower().replace("www.", "")
    except Exception:
        rapport["details"].append(("INVALIDE", 50, "URL invalide"))
        rapport["danger"] = True
        return rapport

    checks = [
        (domaine in LISTE_NOIRE,           100, "LISTE_NOIRE",   "Domaine dans la base de menaces"),
        (parsed.scheme == "http",           10,  "SANS_TLS",     "Pas de chiffrement HTTPS"),
        (any(domaine.endswith(e) for e in EXTENSIONS_RISQUEES), 30, "EXT_RISQUEE",
            f"Extension risquée : {next((e for e in EXTENSIONS_RISQUEES if domaine.endswith(e)), '')}"),
        (bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domaine)), 40, "IP_DIRECTE",  "IP directe"),
        (len(url) > 100,                    15,  "URL_LONGUE",   f"{len(url)} caractères"),
        (len(domaine.split(".")) > 4,       20,  "SOUS_DOMAINES", f"{len(domaine.split('.'))-2} niveaux"),
        ("%" in url or "@" in url,          25,  "CHARS_ENCODES", "Caractères % ou @"),
    ]
    mots = [m for m in MOTS_SUSPECTS if m in url.lower()]
    if mots:
        checks.append((True, len(mots) * 10, "MOTS_PHISHING", ", ".join(mots[:5])))

    for cond, pts, code, msg in checks:
        if cond:
            rapport["score"] += pts
            rapport["details"].append((code, pts, msg))

    rapport["danger"] = rapport["score"] >= 30
    return rapport

# ── Hero statique ─────────────────────────────────────────────────────────────
st.markdown(f"""
<div class="hero">
  {img_html}
  <div class="hero-text">
    <h1>Mal<span>Watch</span></h1>
    <p>Analysez n'importe quelle URL en un clic.<br>Détection de phishing, malwares et sites suspects.</p>
    <div class="hero-badges">
      <span class="badge online">● Système actif</span>
      <span class="badge">8 signatures</span>
      <span class="badge">8 règles</span>
      <span class="badge">100% local</span>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ── Saisie ────────────────────────────────────────────────────────────────────
st.markdown('<div class="url-label">URL à analyser</div>', unsafe_allow_html=True)

url_saisie = st.text_input(
    label="url", value="", placeholder="https://exemple.com",
    label_visibility="collapsed",
)
clic = st.button("🔍  Analyser l'URL")

# ── Session state ─────────────────────────────────────────────────────────────
if "rapport" not in st.session_state:
    st.session_state.rapport = None

if clic and url_saisie.strip():
    st.session_state.rapport = analyser_url(url_saisie.strip())
elif clic and not url_saisie.strip():
    st.warning("Veuillez saisir une URL avant de lancer l'analyse.")

# ── Affichage résultat (100% composants natifs Streamlit) ─────────────────────
rapport = st.session_state.rapport

if rapport is not None:
    score  = min(rapport["score"], 100)
    danger = rapport["danger"]
    url    = rapport["url"]

    try:
        parsed  = urllib.parse.urlparse(url if "://" in url else "http://" + url)
        domaine = parsed.netloc or url
    except Exception:
        domaine = url

    st.markdown("---")

    # ── Verdict principal ──
    if danger:
        st.error(f"## 🚨 Menace détectée\n\n**Ne visitez pas ce site.** Ne saisissez aucune information personnelle et ne téléchargez rien.\n\n`{domaine}`")
    elif score > 0:
        st.warning(f"## ⚠️ Site suspect\n\nCe site présente des points suspects. Vérifiez l'adresse attentivement avant de continuer.\n\n`{domaine}`")
    else:
        st.success(f"## ✅ Aucune menace détectée\n\nNous n'avons détecté aucun signe de danger. Ce site semble sûr.\n\n`{domaine}`")

    # ── Score visuel ──
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.metric(label="Score de risque", value=f"{score} / 100")
        st.progress(score / 100)

    st.markdown("")

    # ── Explications des problèmes ──
    if not rapport["details"]:
        st.info("🛡️ **Tout est en ordre** — Connexion sécurisée, domaine inconnu des bases de menaces, aucun mot-clé suspect.")
    else:
        st.markdown("**Problèmes détectés :**")
        for code, pts, _ in rapport["details"]:
            icone, titre, desc = EXPLICATIONS.get(code, ("⚠️", code, _))
            if pts >= 30:
                st.error(f"{icone} **{titre}**\n\n{desc}")
            else:
                st.warning(f"{icone} **{titre}**\n\n{desc}")

    # ── Journal technique (dépliable) ──
    with st.expander("📋 Journal technique"):
        heure  = time.strftime("%H:%M:%S")
        lignes = [f"[{heure}] Analyse → {url}"]
        for code, pts, _ in rapport["details"]:
            titre_log = EXPLICATIONS.get(code, ("", code, _))[1]
            lignes.append(f"  [{code}] +{pts}pts — {titre_log}")
        vlabel = "DANGEREUX" if danger else ("SUSPECT" if score > 0 else "SUR")
        lignes.append(f"  Score final : {score}/100 → {vlabel}")
        st.code("\n".join(lignes), language=None)

# ── Footer statique ───────────────────────────────────────────────────────────
st.markdown("""
<div class="footer">
  <div class="footer-l"><strong>MalWatch v2.0</strong> — Analyse 100% locale, aucune donnée transmise</div>
  <div class="footer-r">© 2026</div>
</div>
""", unsafe_allow_html=True)