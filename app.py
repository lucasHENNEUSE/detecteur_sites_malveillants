import math
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE = Path(__file__).resolve().parent

# ── Données de référence (tuples / frozenset = immuables et rapides) ──────────
LISTE_NOIRE = frozenset({
    "malware.com", "phishing-site.net", "evil-domain.ru",
    "free-virus.xyz", "steal-data.top", "hack-you.pw",
})
TLD_RISQUES = frozenset({"xyz", "top", "pw", "ru", "tk", "ml", "ga", "cf", "cc", "su", "click", "zip", "work", "gq"})
RACCOURCISSEURS = frozenset({"bit.ly", "goo.gl", "tinyurl.com", "t.co", "is.gd", "ow.ly", "cutt.ly"})
MOTS_SUSPECTS = ("login", "signin", "secure", "account", "verify", "update", "banking", "password",
                 "confirm", "wallet", "suspend", "gratuit", "free", "bonus", "colis")
MARQUES = ("paypal", "amazon", "google", "microsoft", "apple", "adobe", "netflix", "facebook",
           "instagram", "whatsapp", "linkedin", "dropbox", "orange", "laposte", "ameli", "impots",
           "boursorama", "creditagricole", "bnpparibas", "societegenerale", "chronopost",
           "colissimo", "steam", "discord", "binance", "coinbase")
DOMAINES_SURS = frozenset({
    "paypal.com", "amazon.com", "amazon.fr", "google.com", "google.fr", "microsoft.com", "apple.com",
    "adobe.com", "netflix.com", "facebook.com", "instagram.com", "whatsapp.com", "linkedin.com",
    "dropbox.com", "orange.fr", "laposte.fr", "ameli.fr", "impots.gouv.fr", "boursorama.com",
    "credit-agricole.fr", "bnpparibas.com", "societegenerale.fr", "chronopost.fr", "colissimo.fr",
    "steampowered.com", "discord.com", "binance.com", "coinbase.com", "github.com", "wikipedia.org",
    "youtube.com", "anthropic.com", "claude.ai",
})
SLD = frozenset({"co", "com", "org", "net", "gouv", "gov", "ac"})
LEET = str.maketrans("01358", "oleba")
RE_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
RE_IP_OBFUSQUEE = re.compile(r"^(0x[0-9a-f]+|\d{8,10})$", re.I)

# ── Modèle : régression logistique  p = σ(biais +  poids·x)

CARACTERISTIQUES = (
    ("LISTE_NOIRE",    8.0, "Domaine connu comme malveillant"),
    ("SANS_TLS",       0.6, "Connexion non chiffrée (HTTP)"),
    ("TLD_RISQUE",     1.6, "Extension de domaine souvent abusée"),
    ("IP_DIRECTE",     2.4, "Adresse IP à la place d'un nom de domaine"),
    ("IP_OBFUSQUEE",   3.0, "Adresse IP masquée (hexadécimal / décimal)"),
    ("URL_LONGUE",     0.8, "Lien anormalement long"),
    ("SOUS_DOMAINES",  1.0, "Trop de sous-domaines"),
    ("ARROBASE",       2.2, "Identifiant caché avant le « @ » : technique de leurre"),
    ("ENCODAGE",       0.9, "Caractères encodés (%) pour masquer l'adresse"),
    ("PUNYCODE",       1.8, "Caractères trompeurs (homographes IDN)"),
    ("RACCOURCISSEUR", 1.5, "Lien raccourci : destination cachée"),
    ("ENTROPIE",       1.4, "Nom de domaine d'aspect aléatoire"),
    ("CHIFFRES",       1.0, "Proportion élevée de chiffres dans le nom"),
    ("TIRETS",         0.9, "Nombreux tirets dans le nom de domaine"),
    ("MOTS_PHISHING",  1.1, "Vocabulaire typique du phishing"),
    ("TYPOSQUATTING",  3.6, "Imite l'orthographe d'une grande marque"),
    ("MARQUE_USURPEE", 3.2, "Utilise le nom d'une marque sans lui appartenir"),
    ("DOMAINE_SUR",   -4.5, "Domaine officiel d'une marque reconnue"),
)
BIAIS = -3.4
IDX = {c[0]: i for i, c in enumerate(CARACTERISTIQUES)}


def entropie(texte: str) -> float:
    if not texte:
        return 0.0
    n = len(texte)
    return -sum(f / n * math.log2(f / n) for f in Counter(texte).values())


def levenshtein(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 3
    prec = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prec[j] + 1, cur[j - 1] + 1, prec[j - 1] + (ca != cb)))
        prec = cur
    return prec[-1]


def clamp(v: float) -> float:
    return 0.0 if v < 0 else 1.0 if v > 1 else v


def domaine_enregistre(labels: list) -> list:
    """Retourne les labels du domaine principal (gère .co.uk, .gouv.fr…)."""
    if len(labels) >= 3 and labels[-2] in SLD and len(labels[-1]) == 2:
        return labels[-3:]
    return labels[-2:]


def extraire(url: str):
    """Transforme l'URL en vecteur de caractéristiques (tuple aligné sur CARACTERISTIQUES)."""
    p = urlparse(url)
    hote = (p.hostname or "").lower().rstrip(".")
    if not hote or " " in hote or ("." not in hote and ":" not in hote):
        raise ValueError("hôte invalide")
    labels = hote.split(".")
    reg_labels = domaine_enregistre(labels)
    reg = ".".join(reg_labels)
    nom = reg_labels[0] if len(reg_labels) > 1 else hote
    tld = labels[-1]
    sur = reg in DOMAINES_SURS
    texte = hote + (p.path or "").lower() + (p.query or "").lower()
    ip = bool(RE_IPV4.match(hote))

    x = [0.0] * len(CARACTERISTIQUES)
    x[IDX["LISTE_NOIRE"]] = float(reg in LISTE_NOIRE)
    x[IDX["SANS_TLS"]] = float(p.scheme == "http")
    x[IDX["TLD_RISQUE"]] = float(tld in TLD_RISQUES)
    x[IDX["IP_DIRECTE"]] = float(ip)
    x[IDX["IP_OBFUSQUEE"]] = float(bool(RE_IP_OBFUSQUEE.match(hote)))
    x[IDX["URL_LONGUE"]] = clamp((len(url) - 75) / 100)
    x[IDX["SOUS_DOMAINES"]] = clamp((len(labels) - len(reg_labels) - 1) / 3)
    x[IDX["ARROBASE"]] = float("@" in p.netloc)
    x[IDX["ENCODAGE"]] = clamp(url.count("%") / 5)
    x[IDX["PUNYCODE"]] = float("xn--" in hote)
    x[IDX["RACCOURCISSEUR"]] = float(reg in RACCOURCISSEURS)
    if not ip and len(nom) >= 8:
        x[IDX["ENTROPIE"]] = clamp((entropie(nom) - 3.0) / 1.2)
    if not ip and len(nom) >= 4:
        x[IDX["CHIFFRES"]] = clamp(sum(c.isdigit() for c in nom) / len(nom) * 3)
    x[IDX["TIRETS"]] = clamp(hote.count("-") / 3)
    x[IDX["MOTS_PHISHING"]] = clamp(sum(m in texte for m in MOTS_SUSPECTS) / 3)
    x[IDX["DOMAINE_SUR"]] = float(sur)

    if not sur and not ip:
        norm = nom.translate(LEET)
        for m in MARQUES:
            if nom != m and (norm == m or (len(m) >= 5 and levenshtein(norm, m) <= 1)):
                x[IDX["TYPOSQUATTING"]] = 1.0
                break
        for m in MARQUES:
            if m in hote:
                x[IDX["MARQUE_USURPEE"]] = 1.0
                break
            if m in texte:
                x[IDX["MARQUE_USURPEE"]] = max(x[IDX["MARQUE_USURPEE"]], 0.5)
    return tuple(x)


@lru_cache(maxsize=4096)
def analyser_url(url: str) -> dict:
    brut = url.strip()
    url = brut if re.match(r"^[a-z][a-z0-9+.-]*://", brut, re.I) else "http://" + brut
    try:
        x = extraire(url)
    except ValueError:
        return {"url": brut, "score": 50, "niveau": "suspect", "danger": False,
                "details": (("INVALIDE", 50, "Adresse illisible ou incomplète."),)}

    z = BIAIS
    details = []
    for (code, poids, msg), v in zip(CARACTERISTIQUES, x):
        if v:
            z += poids * v
            details.append((code, round(poids * v * 10), msg))
    details.sort(key=lambda d: -d[1])
    score = round(100 / (1 + math.exp(-z)))
    niveau = "danger" if score >= 50 else "suspect" if score >= 20 else "sain"
    return {"url": brut, "score": score, "niveau": niveau,
            "danger": niveau == "danger", "details": tuple(details)}


# ── Serveur FastAPI ───────────────────────────────────────────────────────────
app = FastAPI(title="MalWatch API", version="2.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


class AnalyzeRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


@app.post("/api/analyze")
def api_analyze_url(req: AnalyzeRequest):
    return analyser_url(req.url)


@app.get("/api/health")
def health():
    return {"ok": True}


def trouver(nom: str):
    """Cherche un fichier/dossier à la racine du projet, puis dans template/ ou static/."""
    for base in (BASE, BASE / "template", BASE / "templates", BASE / "static"):
        if (base / nom).exists():
            return base / nom
    return None


@app.get("/")
def serve_frontend():
    page = trouver("index.html")
    if page is None:
        return HTMLResponse(f"<h3>index.html introuvable</h3><p>Place-le dans : {BASE}</p>", status_code=404)
    return FileResponse(page)


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)


# Dossiers d'images de l'avatar (/fixe/1.png, /parler/2.png…)
for dossier in ("fixe", "parler", "chercher", "gagner", "perdu"):
    chemin = trouver(dossier)
    if chemin and chemin.is_dir():
        app.mount(f"/{dossier}", StaticFiles(directory=chemin), name=dossier)

if __name__ == "__main__":
    print("MalWatch → http://127.0.0.1:8000")
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)