"""
╔══════════════════════════════════════════════════╗
║     🛡️  MALWATCH — Détecteur de Sites Malveillants ║
╚══════════════════════════════════════════════════╝
Interface graphique avancée avec tkinter
"""

import re
import urllib.parse
import tkinter as tk
from tkinter import font as tkfont
import time

COULEURS = {
    "fond":           "#070b14",
    "panneau":        "#0d1424",
    "bordure":        "#1a2744",
    "accent":         "#00e5ff",
    "accent_sombre":  "#007a8a",
    "danger":         "#ff2d55",
    "danger_sombre":  "#7a0020",
    "avertissement":  "#ffb300",
    "securite":       "#00e676",
    "securite_som":   "#004d26",
    "texte":          "#c8d8f0",
    "texte_sombre":   "#4a6080",
    "texte_vif":      "#ffffff",
    "grille":         "#0d1a2e",
}

LISTE_NOIRE = {
    "malware.com", "phishing-site.net", "evil-domain.ru",
    "free-virus.xyz", "steal-data.top", "hack-you.pw",
    "click-here-win.com", "update-virus.info",
}

MOTS_SUSPECTS = [
    "login", "secure", "account", "verify", "update",
    "banking", "paypal", "amazon", "free", "win", "prize",
    "urgent", "suspended", "confirm", "password", "wallet",
    "crypto", "invoice", "alert", "click", "download",
]

EXTENSIONS_RISQUEES = [".xyz", ".top", ".pw", ".ru", ".tk", ".ml", ".ga", ".cf"]


def analyser_url(url: str) -> dict:
    rapport = {"url": url, "danger": False, "score": 0, "raisons": [], "details": []}

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        analyse = urllib.parse.urlparse(url)
        domaine = analyse.netloc.lower().replace("www.", "")
    except Exception:
        rapport["raisons"].append("URL invalide ou malformée")
        rapport["danger"] = True
        return rapport

    verifications = [
        (domaine in LISTE_NOIRE, 100, "LISTE_NOIRE", "Domaine référencé dans la base de menaces"),
        (analyse.scheme == "http", 10, "SANS_TLS", "Connexion non chiffrée — HTTP sans certificat SSL"),
        (any(domaine.endswith(e) for e in EXTENSIONS_RISQUEES), 30, "EXT_RISQUEE",
            f"Extension à haut risque : {next((e for e in EXTENSIONS_RISQUEES if domaine.endswith(e)), '')}"),
        (bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domaine)), 40, "IP_DIRECTE",
            "Cible une adresse IP directe — contournement DNS suspect"),
        (len(url) > 100, 15, "URL_LONGUE", f"URL anormalement longue ({len(url)} caractères)"),
        (len(domaine.split(".")) > 4, 20, "SOUS_DOMAINES",
            f"Abus de sous-domaines : {len(domaine.split('.'))-2} niveaux"),
        ("%" in url or "@" in url, 25, "CHARS_ENCODES",
            "Caractères d'encodage ou redirecteur '@' présents"),
    ]

    mots = [m for m in MOTS_SUSPECTS if m in url.lower()]
    if mots:
        verifications.append((True, len(mots) * 10, "MOTS_HAMEÇONNAGE",
            f"Mots-clés de phishing : {', '.join(mots[:5])}"))

    for condition, points, code, message in verifications:
        if condition:
            rapport["score"] += points
            rapport["raisons"].append(message)
            rapport["details"].append((code, points, message))

    rapport["danger"] = rapport["score"] >= 30
    return rapport


class ApplicationMalwatch:
    def __init__(self):
        self.racine = tk.Tk()
        self.racine.title("MALWATCH — Système de Détection des Menaces")
        self.racine.geometry("760x640")
        self.racine.configure(bg=COULEURS["fond"])
        self.racine.resizable(False, False)
        self._configurer_polices()
        self._construire_interface()
        self._animer_voyant()

    def _configurer_polices(self):
        self.p_titre   = tkfont.Font(family="Courier New", size=18, weight="bold")
        self.p_sous    = tkfont.Font(family="Courier New", size=9)
        self.p_label   = tkfont.Font(family="Courier New", size=10, weight="bold")
        self.p_saisie  = tkfont.Font(family="Courier New", size=12)
        self.p_code    = tkfont.Font(family="Courier New", size=9)
        self.p_statut  = tkfont.Font(family="Courier New", size=22, weight="bold")
        self.p_score   = tkfont.Font(family="Courier New", size=13, weight="bold")
        self.p_bouton  = tkfont.Font(family="Courier New", size=11, weight="bold")
        self.p_etiq    = tkfont.Font(family="Courier New", size=8, weight="bold")

    def _construire_interface(self):
        # EN-TÊTE
        entete = tk.Frame(self.racine, bg=COULEURS["panneau"])
        entete.pack(fill="x")
        tk.Frame(entete, bg=COULEURS["accent"], height=2).pack(fill="x")
        interieur = tk.Frame(entete, bg=COULEURS["panneau"], padx=24, pady=14)
        interieur.pack(fill="x")
        gauche = tk.Frame(interieur, bg=COULEURS["panneau"])
        gauche.pack(side="left")
        tk.Label(gauche, text="⬡ MALWATCH", font=self.p_titre,
                 bg=COULEURS["panneau"], fg=COULEURS["accent"]).pack(anchor="w")
        tk.Label(gauche, text="SYSTÈME DE DÉTECTION DES MENACES  v2.0",
                 font=self.p_sous, bg=COULEURS["panneau"], fg=COULEURS["texte_sombre"]).pack(anchor="w")
        droite = tk.Frame(interieur, bg=COULEURS["panneau"])
        droite.pack(side="right")
        self.voyant_statut = tk.Label(droite, text="●  SYSTÈME ACTIF",
                                      font=self.p_sous, bg=COULEURS["panneau"], fg=COULEURS["securite"])
        self.voyant_statut.pack(anchor="e")
        tk.Label(droite, text="BASE : 8 SIGNATURES | 8 RÈGLES",
                 font=self.p_sous, bg=COULEURS["panneau"], fg=COULEURS["texte_sombre"]).pack(anchor="e")
        tk.Frame(entete, bg=COULEURS["bordure"], height=1).pack(fill="x")

        # SAISIE
        cadre_saisie = tk.Frame(self.racine, bg=COULEURS["fond"], padx=24, pady=18)
        cadre_saisie.pack(fill="x")
        tk.Label(cadre_saisie, text="URL CIBLE", font=self.p_label,
                 bg=COULEURS["fond"], fg=COULEURS["texte_sombre"]).pack(anchor="w", pady=(0, 5))
        rangee = tk.Frame(cadre_saisie, bg=COULEURS["fond"])
        rangee.pack(fill="x")
        cadre_bordure = tk.Frame(rangee, bg=COULEURS["accent_sombre"], padx=1, pady=1)
        cadre_bordure.pack(side="left", fill="x", expand=True)
        int_saisie = tk.Frame(cadre_bordure, bg=COULEURS["panneau"])
        int_saisie.pack(fill="both")
        self.var_url = tk.StringVar()
        self.champ = tk.Entry(int_saisie, textvariable=self.var_url,
                              font=self.p_saisie, bg=COULEURS["panneau"], fg=COULEURS["accent"],
                              insertbackground=COULEURS["accent"], relief="flat", bd=10)
        self.champ.pack(fill="x")
        self.champ.insert(0, "https://exemple.com")
        self.champ.bind("<Return>", lambda e: self._lancer_analyse())
        self.bouton = tk.Button(rangee, text="  ANALYSER  ", font=self.p_bouton,
                                bg=COULEURS["accent"], fg=COULEURS["fond"], relief="flat", bd=0,
                                padx=12, pady=8, cursor="hand2",
                                activebackground=COULEURS["accent_sombre"],
                                activeforeground=COULEURS["texte_vif"],
                                command=self._lancer_analyse)
        self.bouton.pack(side="left", padx=(10, 0))

        # CARTE RÉSULTAT
        cadre_resultat = tk.Frame(self.racine, bg=COULEURS["fond"], padx=24)
        cadre_resultat.pack(fill="x")
        self.carte_resultat = tk.Frame(cadre_resultat, bg=COULEURS["panneau"],
                                       highlightthickness=1,
                                       highlightbackground=COULEURS["bordure"])
        self.carte_resultat.pack(fill="x")
        int_carte = tk.Frame(self.carte_resultat, bg=COULEURS["panneau"], padx=20, pady=16)
        int_carte.pack(fill="x")
        gauche_carte = tk.Frame(int_carte, bg=COULEURS["panneau"])
        gauche_carte.pack(side="left", fill="y")
        self.lbl_statut = tk.Label(gauche_carte, text="⬡  EN ATTENTE",
                                   font=self.p_statut, bg=COULEURS["panneau"],
                                   fg=COULEURS["texte_sombre"])
        self.lbl_statut.pack(anchor="w")
        self.lbl_domaine = tk.Label(gauche_carte, text="─── Aucune URL analysée",
                                    font=self.p_code, bg=COULEURS["panneau"],
                                    fg=COULEURS["texte_sombre"])
        self.lbl_domaine.pack(anchor="w", pady=(4, 0))
        droite_carte = tk.Frame(int_carte, bg=COULEURS["panneau"])
        droite_carte.pack(side="right", anchor="n")
        tk.Label(droite_carte, text="SCORE DE RISQUE", font=self.p_etiq,
                 bg=COULEURS["panneau"], fg=COULEURS["texte_sombre"]).pack(anchor="e")
        self.lbl_score = tk.Label(droite_carte, text="— / 100",
                                  font=self.p_score, bg=COULEURS["panneau"],
                                  fg=COULEURS["texte_sombre"])
        self.lbl_score.pack(anchor="e")
        self.barre_fond = tk.Frame(droite_carte, bg=COULEURS["bordure"], width=180, height=6)
        self.barre_fond.pack(anchor="e", pady=(4, 0))
        self.barre_fond.pack_propagate(False)
        self.barre_remplie = tk.Frame(self.barre_fond, bg=COULEURS["texte_sombre"], height=6, width=0)
        self.barre_remplie.pack(side="left")

        # SÉPARATEUR
        tk.Frame(self.racine, bg=COULEURS["bordure"], height=1).pack(fill="x", padx=24, pady=(14, 0))

        # JOURNAL
        ext_journal = tk.Frame(self.racine, bg=COULEURS["fond"], padx=24, pady=12)
        ext_journal.pack(fill="both", expand=True)
        rangee_entete = tk.Frame(ext_journal, bg=COULEURS["fond"])
        rangee_entete.pack(fill="x", pady=(0, 8))
        tk.Label(rangee_entete, text="JOURNAL DE DÉTECTION", font=self.p_label,
                 bg=COULEURS["fond"], fg=COULEURS["texte_sombre"]).pack(side="left")
        self.lbl_compteur = tk.Label(rangee_entete, text="", font=self.p_etiq,
                                     bg=COULEURS["fond"], fg=COULEURS["texte_sombre"])
        self.lbl_compteur.pack(side="right")
        conteneur_journal = tk.Frame(ext_journal, bg=COULEURS["panneau"],
                                     highlightthickness=1,
                                     highlightbackground=COULEURS["bordure"])
        conteneur_journal.pack(fill="both", expand=True)
        barre_defilement = tk.Scrollbar(conteneur_journal, bg=COULEURS["bordure"],
                                        troughcolor=COULEURS["panneau"], relief="flat", bd=0)
        barre_defilement.pack(side="right", fill="y")
        self.texte_journal = tk.Text(conteneur_journal, font=self.p_code,
                                     bg=COULEURS["panneau"], fg=COULEURS["texte"],
                                     insertbackground=COULEURS["accent"], relief="flat", bd=12,
                                     yscrollcommand=barre_defilement.set, state="disabled",
                                     wrap="word", cursor="arrow", spacing1=3, spacing3=3)
        self.texte_journal.pack(fill="both", expand=True)
        barre_defilement.config(command=self.texte_journal.yview)
        self.texte_journal.tag_configure("heure",        foreground=COULEURS["texte_sombre"])
        self.texte_journal.tag_configure("danger",       foreground=COULEURS["danger"])
        self.texte_journal.tag_configure("avertissement",foreground=COULEURS["avertissement"])
        self.texte_journal.tag_configure("securite",     foreground=COULEURS["securite"])
        self.texte_journal.tag_configure("code",         foreground=COULEURS["accent"])
        self.texte_journal.tag_configure("sombre",       foreground=COULEURS["texte_sombre"])
        self.texte_journal.tag_configure("gras",         foreground=COULEURS["texte_vif"],
                                         font=self.p_label)

        # PIED DE PAGE
        pied = tk.Frame(self.racine, bg=COULEURS["panneau"], padx=24, pady=7)
        pied.pack(fill="x", side="bottom")
        tk.Frame(pied, bg=COULEURS["bordure"], height=1).pack(fill="x", pady=(0, 6))
        tk.Label(pied,
                 text="⬡ Analyse 100% locale — Aucune donnée transmise — Appuyez ENTRÉE ou ANALYSER",
                 font=self.p_sous, bg=COULEURS["panneau"], fg=COULEURS["texte_sombre"]).pack()

        self._init_journal()

    def _init_journal(self):
        self._ecrire_journal("\n  DÉTECTION DES MENACES MALWATCH v2.0\n", "gras")
        self._ecrire_journal("  ─────────────────────────────────────────────\n", "sombre")
        self._ecrire_journal("  Système initialisé. Entrez une URL et lancez l'analyse.\n", "sombre")
        self._ecrire_journal("  ─────────────────────────────────────────────\n\n", "sombre")

    def _ecrire_journal(self, texte, etiquette=""):
        self.texte_journal.config(state="normal")
        if etiquette:
            self.texte_journal.insert("end", texte, etiquette)
        else:
            self.texte_journal.insert("end", texte)
        self.texte_journal.see("end")
        self.texte_journal.config(state="disabled")

    def _separateur_journal(self):
        self._ecrire_journal("  ─────────────────────────────────────────────\n", "sombre")

    def _lancer_analyse(self):
        url = self.var_url.get().strip()
        if not url:
            return
        self.bouton.config(state="disabled", text=" ANALYSE...", bg=COULEURS["accent_sombre"])
        self.lbl_statut.config(text="⬡  ANALYSE...", fg=COULEURS["avertissement"])
        self.racine.after(80, lambda: self._executer_analyse(url))

    def _executer_analyse(self, url):
        rapport = analyser_url(url)
        self._afficher_rapport(rapport)
        self.bouton.config(state="normal", text="  ANALYSER  ", bg=COULEURS["accent"])

    def _afficher_rapport(self, rapport):
        score = rapport["score"]
        danger = rapport["danger"]
        url = rapport["url"]
        try:
            analyse = urllib.parse.urlparse(url if "://" in url else "http://" + url)
            domaine = analyse.netloc or url
        except Exception:
            domaine = url

        if danger:
            couleur_statut = COULEURS["danger"]
            texte_statut   = "⬡  MENACE DÉTECTÉE"
            couleur_barre  = COULEURS["danger"]
        elif score > 0:
            couleur_statut = COULEURS["avertissement"]
            texte_statut   = "⬡  SUSPECT"
            couleur_barre  = COULEURS["avertissement"]
        else:
            couleur_statut = COULEURS["securite"]
            texte_statut   = "⬡  AUCUNE MENACE"
            couleur_barre  = COULEURS["securite"]

        self.lbl_statut.config(text=texte_statut, fg=couleur_statut)
        self.lbl_domaine.config(text=f"─── {domaine}", fg=COULEURS["texte"])
        self.lbl_score.config(text=f"{min(score, 100)} / 100", fg=couleur_statut)
        self.carte_resultat.config(highlightbackground=couleur_statut)
        largeur_cible = int(min(score, 100) / 100 * 180)
        self.barre_remplie.config(bg=couleur_barre, width=0)
        self._animer_barre(largeur_cible, couleur_barre)

        heure = time.strftime("%H:%M:%S")
        self._separateur_journal()
        self._ecrire_journal(f"  [{heure}] ", "heure")
        self._ecrire_journal(f"ANALYSE → {url}\n", "gras")
        if not rapport["details"]:
            self._ecrire_journal("  ✓  ", "securite")
            self._ecrire_journal("Aucune anomalie détectée — Site considéré sûr\n")
        else:
            for code, pts, msg in rapport["details"]:
                icone = "✕" if pts >= 30 else "!"
                etiq  = "danger" if pts >= 30 else "avertissement"
                self._ecrire_journal(f"  [{icone}] ", etiq)
                self._ecrire_journal(f"[{code}] ", "code")
                self._ecrire_journal(f"+{pts:>3}pts  {msg}\n")
        self._ecrire_journal(f"\n       SCORE FINAL : {score}/100  →  ", "sombre")
        verdict = "DANGEREUX" if danger else ("SUSPECT" if score > 0 else "SÛR")
        etiq_v  = "danger" if danger else ("avertissement" if score > 0 else "securite")
        self._ecrire_journal(f"{verdict}\n\n", etiq_v)
        nb = len(rapport["details"])
        self.lbl_compteur.config(
            text=f"  {nb} ALERTE{'S' if nb > 1 else ''}" if nb else "  0 ALERTE",
            fg=COULEURS["danger"] if danger else (COULEURS["avertissement"] if nb > 0 else COULEURS["securite"])
        )
        if danger:
            self.racine.after(200, lambda: self._popup_danger(rapport))

    def _animer_barre(self, cible, couleur, actuel=0, pas=4):
        if actuel < cible:
            suivant = min(actuel + pas, cible)
            self.barre_remplie.config(width=suivant)
            self.racine.after(12, lambda: self._animer_barre(cible, couleur, suivant, pas))

    def _popup_danger(self, rapport):
        fenetre = tk.Toplevel(self.racine)
        fenetre.title("⛔ ALERTE SÉCURITÉ")
        fenetre.geometry("480x340")
        fenetre.configure(bg=COULEURS["fond"])
        fenetre.resizable(False, False)
        fenetre.grab_set()
        tk.Frame(fenetre, bg=COULEURS["danger"], height=3).pack(fill="x")
        contenu = tk.Frame(fenetre, bg=COULEURS["fond"], padx=28, pady=20)
        contenu.pack(fill="both", expand=True)
        tk.Label(contenu, text="⛔ MENACE DÉTECTÉE",
                 font=self.p_statut, bg=COULEURS["fond"], fg=COULEURS["danger"]).pack(anchor="w")
        url_courte = rapport["url"][:60] + ("..." if len(rapport["url"]) > 60 else "")
        tk.Label(contenu, text=url_courte, font=self.p_code,
                 bg=COULEURS["fond"], fg=COULEURS["texte_sombre"]).pack(anchor="w", pady=(4, 12))
        tk.Frame(contenu, bg=COULEURS["bordure"], height=1).pack(fill="x", pady=(0, 10))
        for _, pts, msg in rapport["details"][:5]:
            rangee = tk.Frame(contenu, bg=COULEURS["fond"])
            rangee.pack(fill="x", pady=2)
            couleur_etiq = COULEURS["danger"] if pts >= 30 else COULEURS["avertissement"]
            tk.Label(rangee, text="●", font=self.p_code, bg=COULEURS["fond"],
                     fg=couleur_etiq).pack(side="left", padx=(0, 8))
            tk.Label(rangee, text=msg, font=self.p_code, bg=COULEURS["fond"],
                     fg=COULEURS["texte"], wraplength=380, justify="left").pack(side="left")
        tk.Frame(contenu, bg=COULEURS["bordure"], height=1).pack(fill="x", pady=(10, 12))
        tk.Button(contenu, text="  COMPRIS — FERMER  ", font=self.p_bouton,
                  bg=COULEURS["danger"], fg=COULEURS["texte_vif"], relief="flat", bd=0,
                  padx=10, pady=8, cursor="hand2",
                  command=fenetre.destroy).pack(anchor="e")

    def _animer_voyant(self):
        couleurs = [COULEURS["securite"], COULEURS["securite_som"]]
        self._idx_voyant = 0
        def basculer():
            self._idx_voyant = (self._idx_voyant + 1) % 2
            try:
                self.voyant_statut.config(fg=couleurs[self._idx_voyant])
                self.racine.after(900, basculer)
            except Exception:
                pass
        basculer()

    def lancer(self):
        self.racine.mainloop()


if __name__ == "__main__":
    app = ApplicationMalwatch()
    app.lancer()