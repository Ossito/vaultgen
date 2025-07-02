import secrets
import time
import tkinter as tk
from tkinter import ttk, messagebox
import string
import hashlib
import requests
import threading
import re
import math
from tkinter import font as tkfont

def is_valid_email(email):
    # Regex simple mais solide pour vérifier les emails
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None

def generate_identifier(length, use_upper, use_digits, exclude_ambiguous):
    base_chars = string.ascii_lowercase
    if use_upper:
        base_chars += string.ascii_uppercase
    if use_digits:
        base_chars += string.digits

    if exclude_ambiguous:
        ambiguous = "lI1O0|"
        base_chars = ''.join(c for c in base_chars if c not in ambiguous)

    if not base_chars or length < 4:
        return "user123"

    return ''.join(secrets.choice(base_chars) for _ in range(length))

DEFAULT_WORDS = [
    "maison", "soleil", "chien", "chat", "arbre",
    "voiture", "ordinateur", "musique", "livre", "avion"
]

class VaultGenApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 VAULTGEN")
        self.root.geometry("650x700")
        self.root.resizable(False, False)

        # Polices
        self.main_font = tkfont.Font(family='Helvetica', size=10)
        self.title_font = tkfont.Font(family='Helvetica', size=12, weight='bold')

        self.create_widgets()


    def create_widgets(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        self.pwd_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.pwd_tab, text="Mot de Passe")

        self.id_pwd_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.id_pwd_tab, text="ID + Mot de Passe")

        self.verification_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.verification_tab, text="Vérification Mot de Passe")

        self.attack_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.attack_tab, text="Test de Résistance")

        self.setup_password_tab()
        self.setup_id_password_tab()
        self.verification_password_tab()  
        self.setup_attack_tab()  


    def setup_password_tab(self):
        frame = ttk.Frame(self.pwd_tab, padding=15)
        frame.pack(fill=tk.BOTH, expand=True)

        # Conteneur principal pour les configurations (avant le bouton)
        config_container = ttk.Frame(frame)
        config_container.pack(fill=tk.X, pady=5)

        # Mode de génération
        mode_frame = ttk.LabelFrame(config_container, text="Type de génération", padding=10)
        mode_frame.pack(fill=tk.X, pady=5)
        
        self.generation_mode = tk.StringVar(value="password")
        ttk.Radiobutton(mode_frame, text="Mot de passe classique", variable=self.generation_mode, 
                        value="password", command=self.toggle_generation_mode).grid(row=0, column=0, sticky="w", padx=5)
        ttk.Radiobutton(mode_frame, text="Passphrase", variable=self.generation_mode, 
                        value="passphrase", command=self.toggle_generation_mode).grid(row=0, column=1, sticky="w", padx=5)

        # Frame pour contenir les deux types de configurations
        self.config_frames_container = ttk.Frame(config_container)
        self.config_frames_container.pack(fill=tk.X, pady=5)

        # Configuration mot de passe classique
        self.pwd_config_frame = ttk.LabelFrame(self.config_frames_container, text="Configuration Mot de Passe", padding=10)
        
        # Longueur
        ttk.Label(self.pwd_config_frame, text="Longueur (12-64):").grid(row=0, column=0, sticky="w")
        self.pwd_length = ttk.Spinbox(self.pwd_config_frame, from_=12, to=64, width=5)
        self.pwd_length.set(16)
        self.pwd_length.grid(row=0, column=1, sticky="w", padx=5)

        # Options caractères
        self.pwd_upper = tk.BooleanVar(value=True)
        self.pwd_digits = tk.BooleanVar(value=True)
        self.pwd_symbols = tk.BooleanVar(value=True)
        self.pwd_ambiguous = tk.BooleanVar(value=False)

        ttk.Checkbutton(self.pwd_config_frame, text="Majuscules (A-Z)", variable=self.pwd_upper).grid(row=1, column=0, sticky="w", pady=2)
        ttk.Checkbutton(self.pwd_config_frame, text="Chiffres (0-9)", variable=self.pwd_digits).grid(row=1, column=1, sticky="w", pady=2)
        ttk.Checkbutton(self.pwd_config_frame, text="Symboles (!@#)", variable=self.pwd_symbols).grid(row=2, column=0, sticky="w", pady=2)
        ttk.Checkbutton(self.pwd_config_frame, text="Exclure caractères ambigus", variable=self.pwd_ambiguous).grid(row=2, column=1, sticky="w", pady=2)

        # Configuration passphrase
        self.passphrase_config_frame = ttk.LabelFrame(self.config_frames_container, text="Configuration Passphrase", padding=10)

        # Champ pour les mots personnels
        ttk.Label(self.passphrase_config_frame, text="Mots clés personnels (séparés par des virgules):").grid(row=0, column=0, sticky="w", columnspan=2)
        self.custom_words_entry = ttk.Entry(self.passphrase_config_frame)
        self.custom_words_entry.grid(row=1, column=0, sticky="we", columnspan=2, pady=5)
        self.custom_words_entry.insert(0, "exemple,chien,anniversaire,ville")
        
        # Utiliser les mêmes options que pour les mots de passe classiques
        ttk.Label(self.passphrase_config_frame, text="Longueur (12-64):").grid(row=2, column=0, sticky="w")
        self.passphrase_length = ttk.Spinbox(self.passphrase_config_frame, from_=12, to=64, width=5)
        self.passphrase_length.set(16)
        self.passphrase_length.grid(row=2, column=1, sticky="w", padx=5)

        # Cases à cocher identiques au mode mot de passe
        self.passphrase_upper = tk.BooleanVar(value=True)
        self.passphrase_digits = tk.BooleanVar(value=True)
        self.passphrase_symbols = tk.BooleanVar(value=True)
        self.passphrase_ambiguous = tk.BooleanVar(value=False)

        ttk.Checkbutton(self.passphrase_config_frame, text="Majuscules (A-Z)", variable=self.passphrase_upper).grid(row=3, column=0, sticky="w", pady=2)
        ttk.Checkbutton(self.passphrase_config_frame, text="Chiffres (0-9)", variable=self.passphrase_digits).grid(row=3, column=1, sticky="w", pady=2)
        ttk.Checkbutton(self.passphrase_config_frame, text="Symboles (!@#)", variable=self.passphrase_symbols).grid(row=4, column=0, sticky="w", pady=2)
        ttk.Checkbutton(self.passphrase_config_frame, text="Exclure caractères ambigus", variable=self.passphrase_ambiguous).grid(row=4, column=1, sticky="w", pady=2)

        # Afficher la configuration initiale
        self.pwd_config_frame.pack(fill=tk.X, pady=5)
        self.passphrase_config_frame.pack_forget()

        # Bouton Générer (après toutes les configurations)
        ttk.Button(frame, text="🎲 Générer", command=self.generate_password_only, 
                style='Accent.TButton').pack(pady=10)

        # Affichage du résultat
        result_frame = ttk.Frame(frame)
        result_frame.pack(fill=tk.X, pady=5)
        
        self.password_entry = ttk.Entry(result_frame, font=("Courier", 14), justify='center', show="*")
        self.password_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)
        
        # Bouton afficher/masquer
        self.show_password = tk.BooleanVar(value=False)
        ttk.Button(result_frame, text="👁", width=3, 
                command=lambda: self.toggle_password_visibility(self.password_entry, self.show_password)).pack(side=tk.RIGHT, padx=5)

        # Indicateur de force
        self.pwd_strength_label = ttk.Label(frame, text="", font=self.main_font)
        self.pwd_strength_label.pack(pady=5)

        # Boutons d'action
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(btn_frame, text="📋 Copier", command=self.copy_password_only).pack(side=tk.LEFT, expand=True)
        ttk.Button(btn_frame, text="🔍 Vérifier sécurité", command=self.check_password_security).pack(side=tk.RIGHT, expand=True)
        ttk.Button(btn_frame, text="⚡ Tester résistance", command=self.test_password_resistance).pack(side=tk.RIGHT, expand=True, padx=5) 

        # Initialisation
        self.toggle_generation_mode()
    
    
    def toggle_generation_mode(self):
        """Affiche la configuration appropriée selon le mode sélectionné"""
        if self.generation_mode.get() == "password":
            self.pwd_config_frame.pack(fill=tk.X, pady=5)
            self.passphrase_config_frame.pack_forget()
        else:
            self.passphrase_config_frame.pack(fill=tk.X, pady=5)
            self.pwd_config_frame.pack_forget()


    def toggle_password_visibility(self, entry, var):
        var.set(not var.get())
        entry.config(show="" if var.get() else "*")


    def generate_password_only(self):
        """Génère soit un mot de passe soit une passphrase selon le mode"""
        if self.generation_mode.get() == "passphrase":
            # Génération passphrase avec les nouveaux paramètres
            password = self.generate_passphrase()
            is_passphrase = True
        else:
            # Génération mot de passe classique
            length = int(self.pwd_length.get())
            password = self.generate_password(
                length,
                self.pwd_upper.get(),
                self.pwd_digits.get(),
                self.pwd_symbols.get(),
                self.pwd_ambiguous.get()
            )
            is_passphrase = False
        
        # Affichage du résultat
        self.password_entry.config(show="")
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        
        # Évaluation de la force
        strength, color, msg, _ = self.advanced_evaluate_strength(password, is_passphrase)
        self.pwd_strength_label.config(text=msg, foreground=color)


    def toggle_passphrase_options(self):
        if self.passphrase_mode.get():
            self.passphrase_options_frame.pack(fill="x", pady=5)
        else:
            self.passphrase_options_frame.pack_forget()
    
    def generate_personal_password(self, base_words, length=16, use_upper=True, use_digits=True, use_symbols=True, exclude_ambiguous=False):
        """Transforme des mots personnels en mot de passe sécurisé"""
        # Validation des paramètres
        if length < 12:
            length = 12
        elif length > 64:
            length = 64
            
        if not base_words or len(base_words) < 2:
            raise ValueError("Au moins 2 mots requis")

        # 1. Préparation du jeu de caractères
        chars = []
        ambiguous_chars = "lI1O0|"
        
        # Minuscules
        lower_chars = string.ascii_lowercase
        if exclude_ambiguous:
            lower_chars = ''.join(c for c in lower_chars if c not in ambiguous_chars)
        chars.extend(list(lower_chars))
        
        # Majuscules
        if use_upper:
            upper_chars = string.ascii_uppercase
            if exclude_ambiguous:
                upper_chars = ''.join(c for c in upper_chars if c not in ambiguous_chars)
            chars.extend(list(upper_chars))
        
        # Chiffres
        if use_digits:
            digit_chars = string.digits
            if exclude_ambiguous:
                digit_chars = ''.join(c for c in digit_chars if c not in ambiguous_chars)
            chars.extend(list(digit_chars))
        
        # Symboles
        if use_symbols:
            symbol_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?/"
            if exclude_ambiguous:
                symbol_chars = ''.join(c for c in symbol_chars if c not in ambiguous_chars)
            chars.extend(list(symbol_chars))

        # 2. Transformation des mots de base
        processed = []
        for word in base_words:
            word = word.strip()
            if not word:
                continue
                
            # Créer des variations sécurisées
            variations = [
                word,                                   # Original
                word.capitalize(),                      # Première majuscule
                word.upper(),                           # Tout majuscules
                word + (secrets.choice(symbol_chars) if use_symbols else str(secrets.SystemRandom().randint(0, 9))),  # Mot + symbole ou chiffre
                word.translate(str.maketrans('eao', '340')) + str(secrets.SystemRandom().randint(10, 99)),  # Leet speak + 2 chiffres
                ''.join(secrets.choice([c.upper(), c]) for c in word),  # Random case
                word[:len(word)//2] + (secrets.choice(symbol_chars) if use_symbols else str(secrets.SystemRandom().randint(0, 9))) + word[len(word)//2:]  # Symbole/chiffre au milieu
            ]
            
            # Sélection aléatoire de variations
            processed.append(secrets.choice(variations))
        
        # 3. Construction de la base
        secrets.SystemRandom().shuffle(processed)
        base = ''.join(processed)
        
        # 4. Ajout obligatoire de chaque type de caractère
        mandatory = []
        if use_upper and not any(c.isupper() for c in base):
            mandatory.append(secrets.choice(upper_chars))
        if use_digits and not any(c.isdigit() for c in base):
            mandatory.append(secrets.choice(digit_chars))
        if use_symbols and not any(c in symbol_chars for c in base):
            mandatory.append(secrets.choice(symbol_chars))
        
        if mandatory:
            insert_pos = secrets.SystemRandom().randint(0, len(base))
            base = base[:insert_pos] + ''.join(mandatory) + base[insert_pos:]
        
        # 5. Complétion à la longueur souhaitée
        while len(base) < length:
            base += secrets.choice(chars)
        
        # 6. Mélange final
        password = list(base)
        for _ in range(3):  # Multiple shuffles
            secrets.SystemRandom().shuffle(password)
        
        final_pwd = ''.join(password)[:length]
        
        return final_pwd


    def generate_passphrase(self):
        # Récupérer les mots personnels
        custom_words = [w.strip() for w in self.custom_words_entry.get().split(",") if w.strip()]
        
        if not custom_words:
            messagebox.showwarning("Attention", "Veuillez entrer des mots personnels séparés par des virgules")
            return ""
        
        # Générer un mot de passe sécurisé à partir des mots
        password = self.generate_personal_password(
            base_words=custom_words,
            length=int(self.passphrase_length.get()),
            use_upper=self.passphrase_upper.get(),
            use_digits=self.passphrase_digits.get(),
            use_symbols=self.passphrase_symbols.get()
        )
        
        return password
    
    def verify_custom_passphrase(self, passphrase):
        words = passphrase.split(self.separator.get())
        analysis = {
            'unique_words': len(set(words)),
            'total_words': len(words),
            'word_entropy': math.log2(len(self.custom_words)),
            'reused_words': [w for w in words if self.custom_words.count(w) > 1]
        }
        
        # Calcul entropie totale
        total_entropy = analysis['word_entropy'] * analysis['total_words']
        
        # Recommandations
        recommendations = []
        if analysis['unique_words'] < len(words):
            recommendations.append("Évitez les mots répétés dans la passphrase")
        if total_entropy < 60:
            recommendations.append(f"Ajoutez plus de mots (actuellement {analysis['total_words']})")
        if any(len(w) < 4 for w in words):
            recommendations.append("Privilégiez les mots longs (>4 lettres)")
        
        return {
            'entropy': total_entropy,
            'recommendations': recommendations,
            'analysis': analysis
        }

    def setup_id_password_tab(self):
        frame = ttk.Frame(self.id_pwd_tab, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        # ─── Informations utilisateur ───
        user_info = ttk.LabelFrame(frame, text="Informations Utilisateur", padding=10)
        user_info.pack(fill=tk.X, pady=10)

        ttk.Label(user_info, text="Nom complet :").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.full_name_entry = ttk.Entry(user_info)
        self.full_name_entry.grid(row=0, column=1, sticky="we", padx=5, pady=2)

        ttk.Label(user_info, text="Email :").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.email_entry = ttk.Entry(user_info)
        self.email_entry.grid(row=1, column=1, sticky="we", padx=5, pady=2)

        user_info.columnconfigure(1, weight=1)

        # ─── Configuration Identifiant + Mot de passe ───
        config_frame = ttk.Frame(frame)
        config_frame.pack(fill=tk.X, pady=10)

        # Configuration ID
        id_config = ttk.LabelFrame(config_frame, text="Identifiant", padding=10)
        id_config.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        ttk.Label(id_config, text="Longueur :").grid(row=0, column=0, sticky="w", pady=2)
        self.id_length = ttk.Spinbox(id_config, from_=4, to=32, width=5)
        self.id_length.set(8)
        self.id_length.grid(row=0, column=1, sticky="w", pady=2, padx=5)

        self.id_use_upper = tk.BooleanVar(value=False)
        self.id_use_digits = tk.BooleanVar(value=True)
        self.id_exclude_ambiguous = tk.BooleanVar(value=False)

        ttk.Checkbutton(id_config, text="Majuscules (A-Z)", variable=self.id_use_upper).grid(row=1, column=0, columnspan=2, sticky="w", pady=2)
        ttk.Checkbutton(id_config, text="Chiffres (0-9)", variable=self.id_use_digits).grid(row=2, column=0, columnspan=2, sticky="w", pady=2)
        ttk.Checkbutton(id_config, text="Exclure caractères ambigus", variable=self.id_exclude_ambiguous).grid(row=3, column=0, columnspan=2, sticky="w", pady=2)

        # Configuration MDP
        pwd_config = ttk.LabelFrame(config_frame, text="Mot de Passe", padding=10)
        pwd_config.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        ttk.Label(pwd_config, text="Longueur :").grid(row=0, column=0, sticky="w", pady=2)
        self.id_pwd_length = ttk.Spinbox(pwd_config, from_=8, to=64, width=5)
        self.id_pwd_length.set(12)
        self.id_pwd_length.grid(row=0, column=1, sticky="w", pady=2, padx=5)

        self.id_pwd_upper = tk.BooleanVar(value=True)
        self.id_pwd_digits = tk.BooleanVar(value=True)
        self.id_pwd_symbols = tk.BooleanVar(value=True)
        self.id_pwd_ambiguous = tk.BooleanVar(value=False)

        ttk.Checkbutton(pwd_config, text="Majuscules (A-Z)", variable=self.id_pwd_upper).grid(row=1, column=0, columnspan=2, sticky="w", pady=2)
        ttk.Checkbutton(pwd_config, text="Chiffres (0-9)", variable=self.id_pwd_digits).grid(row=2, column=0, columnspan=2, sticky="w", pady=2)
        ttk.Checkbutton(pwd_config, text="Symboles (!@#)", variable=self.id_pwd_symbols).grid(row=3, column=0, columnspan=2, sticky="w", pady=2)
        ttk.Checkbutton(pwd_config, text="Exclure caractères ambigus", variable=self.id_pwd_ambiguous).grid(row=4, column=0, columnspan=2, sticky="w", pady=2)

        # ─── Bouton de génération ───
        ttk.Button(frame, 
                text="🎲 Générer Identifiant + Mot de passe", 
                command=self.generate_id_password).pack(pady=15, fill=tk.X)

        # ─── Résultats ───
        result_frame = ttk.LabelFrame(frame, text="Résultats", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Identifiant
        id_frame = ttk.Frame(result_frame)
        id_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(id_frame, text="Identifiant généré :").pack(side=tk.LEFT, anchor="w")
        self.id_entry = ttk.Entry(id_frame, font=("Courier", 12), justify='center')
        self.id_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        ttk.Button(id_frame, 
                text="📋 Copier", 
                command=lambda: self.copy_to_clipboard(self.id_entry.get(), "Identifiant copié !"))\
            .pack(side=tk.RIGHT)

        # Mot de passe
        pwd_frame = ttk.Frame(result_frame)
        pwd_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(pwd_frame, text="Mot de passe généré :").pack(side=tk.LEFT, anchor="w")
        self.id_pwd_entry = ttk.Entry(pwd_frame, font=("Courier", 12), justify='center', show="*")
        self.id_pwd_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        
        self.show_id_password = tk.BooleanVar(value=False)
        ttk.Button(pwd_frame, text="👁", width=3,
                command=lambda: self.toggle_password_visibility(self.id_pwd_entry, self.show_id_password)).pack(side=tk.RIGHT, padx=(5, 0))
        
        ttk.Button(pwd_frame, 
                text="📋 Copier", 
                command=lambda: self.copy_to_clipboard(self.id_pwd_entry.get(), "Mot de passe copié !"))\
            .pack(side=tk.RIGHT)

        # Force du mot de passe
        self.id_pwd_strength_label = ttk.Label(result_frame, text="", font=self.main_font)
        self.id_pwd_strength_label.pack(pady=(0, 1))

        # Bouton de vérification - plus visible
        btn_frame = ttk.Frame(result_frame)
        btn_frame.pack(fill=tk.X, pady=5)
    
        ttk.Button(
            btn_frame,
            text="🔍 Vérifier sécurité du mot de passe",
            command=self.check_id_password_security,
        ).pack(side=tk.LEFT, expand=True, padx=2)
        
        ttk.Button(
            btn_frame,
            text="⚡ Tester résistance",
            command=self.test_id_password_resistance,
        ).pack(side=tk.LEFT, expand=True, padx=2)  

        self.id_pwd_output_label = ttk.Label(result_frame, text="", font=self.main_font)
        self.id_pwd_output_label.pack(pady=0)


    def verification_password_tab(self):
        frame = ttk.Frame(self.verification_tab, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        # Style
        self.style = ttk.Style()
        self.style.configure('Title.TLabel', font=('Helvetica', 12, 'bold'), foreground='#2c3e50')
        self.style.configure('Good.TLabel', foreground='#27ae60')
        self.style.configure('Warning.TLabel', foreground='#f39c12')
        self.style.configure('Danger.TLabel', foreground='#e74c3c')

        # Conteneur principal
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # Section saisie
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=(0, 15))

        ttk.Label(input_frame, text="Mot de passe à vérifier:", style='Title.TLabel').pack(anchor='w')
        
        entry_frame = ttk.Frame(input_frame)
        entry_frame.pack(fill=tk.X, pady=5)
        
        self.verify_pwd_entry = ttk.Entry(
            entry_frame, 
            font=('Courier', 12),
            show="*",
            width=40
        )
        self.verify_pwd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        # Bouton afficher/masquer
        self.show_verify_password = tk.BooleanVar(value=False)
        ttk.Button(
            entry_frame, 
            text="👁", 
            width=3,
            command=lambda: self.toggle_password_visibility(
                self.verify_pwd_entry, 
                self.show_verify_password
            )
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        # Bouton vérifier
        ttk.Button(
            entry_frame,
            text="🔍 Vérifier",
            command=self.verify_password,
            style='Accent.TButton'
        ).pack(side=tk.LEFT)

        # Section résultats
        self.result_notebook = ttk.Notebook(main_frame)
        self.result_notebook.pack(fill=tk.BOTH, expand=True)

        # Onglet Résumé
        summary_tab = ttk.Frame(self.result_notebook)
        self.result_notebook.add(summary_tab, text="Résumé")
        self.setup_summary_tab(summary_tab)

        # Onglet Analyse détaillée
        analysis_tab = ttk.Frame(self.result_notebook)
        self.result_notebook.add(analysis_tab, text="Analyse")
        self.setup_analysis_tab(analysis_tab)

        # Onglet Recommandations
        recommendations_tab = ttk.Frame(self.result_notebook)
        self.result_notebook.add(recommendations_tab, text="Recommandations")
        self.setup_recommendations_tab(recommendations_tab)

        # Cache pour les requêtes HIBP
        self.hibp_cache = {}
    
    
    def generate_id_password(self):
        # Générer identifiant à partir du nom et email
        full_name = self.full_name_entry.get().strip()
        email = self.email_entry.get().strip()
        
        if not full_name or not email:
            messagebox.showwarning("Attention", "Veuillez entrer votre nom complet et votre email.")
            return

        if not is_valid_email(email):
            messagebox.showerror("Email invalide", "L'adresse email saisie n'est pas valide. Veuillez corriger.")
            return
        
        # Générer un identifiant configurable
        length = int(self.id_length.get())
        identifier = generate_identifier(
            length,
            self.id_use_upper.get(),
            self.id_use_digits.get(),
            self.id_exclude_ambiguous.get()
        )
        self.id_entry.delete(0, tk.END)
        self.id_entry.insert(0, identifier)

        # Mot de passe
        length = int(self.id_pwd_length.get())
        password = self.generate_password(
            length,
            self.id_pwd_upper.get(),
            self.id_pwd_digits.get(),
            self.id_pwd_symbols.get(),
            self.id_pwd_ambiguous.get()
        )
        self.id_pwd_entry.delete(0, tk.END)
        self.id_pwd_entry.insert(0, password)

        strength, color, msg, _ = self.advanced_evaluate_strength(password)
        self.id_pwd_strength_label.config(text=msg, foreground=color)
        self.id_pwd_output_label.config(text="")
    
    def copy_password_only(self):
        password = self.password_entry.get()
        if password:
            self.copy_to_clipboard(password, "Mot de passe copié!")
    
    def copy_to_clipboard(self, text, message):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Succès", message)
    
    def check_id_password_security(self):
        password = self.id_pwd_entry.get()
        if not password:
            messagebox.showwarning("Attention", "Générez d'abord un mot de passe")
            return
        
        self.check_pwned_password(password, self.id_pwd_output_label, None, self.id_pwd_strength_label)

    # Fonctions de génération et vérification (restent identiques)
    def generate_password(self, length, use_upper, use_digits, use_symbols, exclude_ambiguous=False):
        chars = string.ascii_lowercase
        ambiguous = "lI1O0|"
        
        if use_upper:
            chars += string.ascii_uppercase
        if use_digits:
            chars += string.digits
        if use_symbols:
            chars += "!@#$%^&*()-_=+[]{}|;:,.<>?/"
        if exclude_ambiguous:
            chars = ''.join(c for c in chars if c not in ambiguous)

        if length < 8:
            return ""

        password = []
        password.append(secrets.choice(string.ascii_lowercase))
        if use_upper:
            password.append(secrets.choice(string.ascii_uppercase))
        if use_digits:
            password.append(secrets.choice(string.digits))
        if use_symbols:
            password.append(secrets.choice("!@#$%^&*()-_=+[]{}|;:,.<>?/"))

        while len(password) < length:
            password.append(secrets.choice(chars))

        # Utiliser SystemRandom().shuffle() au lieu de secrets.shuffle()
        secrets.SystemRandom().shuffle(password)
        return "".join(password)

    
    def advanced_evaluate_strength(self, pwd, is_passphrase=False):
        # Utiliser la même vérification pour les deux modes
        length = len(pwd)
        categories = sum([
            any(c.islower() for c in pwd),
            any(c.isupper() for c in pwd),
            any(c.isdigit() for c in pwd),
            any(c in "!@#$%^&*" for c in pwd)
        ])
        
        entropy = self.calculate_entropy(pwd)
        
        if length < 12 or categories < 3 or entropy < 60:
            return "🔴 Faible", "red", "Trop faible - Changez immédiatement", "quelques minutes"
        elif entropy < 80:
            return "🟠 Moyen", "orange", "Acceptable mais peut être amélioré", "quelques mois"
        else:
            return "🟢 Fort", "green", "Robuste - Sécurité élevée", "plusieurs siècles"


    def check_password_security(self):
        """Déclenche la vérification de sécurité du mot de passe"""
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Attention", "Générez d'abord un mot de passe")
            return
        
        # Préparation de l'interface
        self.verify_pwd_entry.delete(0, tk.END)
        self.verify_pwd_entry.insert(0, password)
        self.notebook.select(self.verification_tab)
        
        # Affichage du statut de chargement
        self.show_loading_state()
        
        # Lancement de la vérification
        self.root.after(100, self.verify_password)


    def calculate_entropy(self, password):
        symbol_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?/" 
        charset = 0
        if any(c.islower() for c in password): charset += 26
        if any(c.isupper() for c in password): charset += 26  
        if any(c.isdigit() for c in password): charset += 10
        if any(c in symbol_chars for c in password): charset += len(symbol_chars)  # Plus précis
        
        return len(password) * math.log2(charset) if charset else 0


    def check_id_password_security(self):
        password = self.id_pwd_entry.get()
        if not password:
            messagebox.showwarning("Attention", "Générez d'abord un mot de passe")
            return
        
        # Copier le mot de passe dans l'onglet de vérification
        self.verify_pwd_entry.delete(0, tk.END)
        self.verify_pwd_entry.insert(0, password)
        
        # Basculer vers l'onglet de vérification
        self.notebook.select(self.verification_tab)
        
        # Lancer la vérification après un petit délai
        self.root.after(100, self.verify_password)   

    def check_pwned_password(self, pwd, output_label, check_button, strength_label):
        if not pwd:
            messagebox.showwarning("Attention", "Générez d'abord un mot de passe")
            return

        if check_button:
            check_button.config(state=tk.DISABLED)
        output_label.config(text="🔍 Vérification en cours...", foreground="black")

        def worker():
            try:
                sha1pwd = hashlib.sha1(pwd.encode()).hexdigest().upper()
                prefix, suffix = sha1pwd[:5], sha1pwd[5:]
                
                response = requests.get(
                    f"https://api.pwnedpasswords.com/range/{prefix}",
                    timeout=5,
                    headers={"User-Agent": "PasswordGeneratorApp"}
                )
                
                if response.status_code == 200:
                    found = False
                    for line in response.text.splitlines():
                        if line.startswith(suffix):
                            count = int(line.split(":")[1])
                            result = f"⚠️ COMPROMIS {count}x ! Changez-le IMMÉDIATEMENT"
                            color = "red"
                            found = True
                            break
                    
                    if not found:
                        strength, color, msg, _ = self.advanced_evaluate_strength(pwd)
                        result = f"✅ Non compromis - {msg.split(' - ')[1]}"
                        color = "green" if "Robuste" in msg else "orange"
                else:
                    raise Exception(f"Erreur API: {response.status_code}")

            except Exception as e:
                result = f"⚠️ Erreur vérification: {str(e)}"
                color = "red"

            output_label.config(text=result, foreground=color)
            if check_button:
                check_button.config(state=tk.NORMAL)

        threading.Thread(target=worker, daemon=True).start()


    def detailed_password_analysis(self, password):
        # Pré-calcul des caractéristiques
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/" for c in password)
        
        return {
            'length': len(password),
            'has_lower': has_lower,
            'has_upper': has_upper,
            'has_digit': has_digit,
            'has_special': has_special,
            'common_sequences': self.check_common_sequences(password),
            'repetition': self.check_character_repetition(password),
            'entropy': self.calculate_entropy(password, has_lower, has_upper, has_digit, has_special)
        }


    def check_common_sequences(self, password):
        sequences = [
            '123456', 'password', 'azerty', 'qwerty',
            'abcdef', '654321', '111111', 'admin',
            'welcome', 'sunshine', 'letmein'
        ]
        password_lower = password.lower()
        return any(seq in password_lower for seq in sequences)

    def check_character_repetition(self, password):
        return bool(re.search(r'(.)\1{2,}', password))

    def setup_summary_tab(self, parent):
        frame = ttk.Frame(parent, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        # Score global
        self.score_frame = ttk.Frame(frame)
        self.score_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(
            self.score_frame, 
            text="Score de sécurité:", 
            style='Title.TLabel'
        ).pack(anchor='w')
        
        self.score_label = ttk.Label(
            self.score_frame, 
            text="Non évalué", 
            font=('Helvetica', 24, 'bold')
        )
        self.score_label.pack(pady=10)
        
        # Barre de score
        self.score_meter = ttk.Progressbar(
            self.score_frame,
            orient='horizontal',
            mode='determinate',
            length=400
        )
        self.score_meter.pack(fill=tk.X)
        
        # Statut HIBP
        self.hibp_status_frame = ttk.Frame(frame)
        self.hibp_status_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Label(
            self.hibp_status_frame, 
            text="Statut de compromission:", 
            style='Title.TLabel'
        ).pack(anchor='w')
        
        self.hibp_status_label = ttk.Label(
            self.hibp_status_frame, 
            text="Non vérifié",
            font=('Helvetica', 12)
        )
        self.hibp_status_label.pack(pady=5)

    def setup_analysis_tab(self, parent):
        frame = ttk.Frame(parent, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview pour les résultats d'analyse
        columns = ('criteria', 'status', 'value')
        self.analysis_tree = ttk.Treeview(
            frame,
            columns=columns,
            show='headings',
            selectmode='none',
            height=8
        )
        
        # Configuration des colonnes
        self.analysis_tree.heading('criteria', text='Critère')
        self.analysis_tree.heading('status', text='Statut')
        self.analysis_tree.heading('value', text='Valeur')
        
        self.analysis_tree.column('criteria', width=200, anchor='w')
        self.analysis_tree.column('status', width=100, anchor='center')
        self.analysis_tree.column('value', width=150, anchor='w')
        
        self.analysis_tree.pack(fill=tk.BOTH, expand=True)
        
        # Barre de défilement
        scrollbar = ttk.Scrollbar(
            frame,
            orient='vertical',
            command=self.analysis_tree.yview
        )
        scrollbar.pack(side='right', fill='y')
        self.analysis_tree.configure(yscrollcommand=scrollbar.set)

    def setup_recommendations_tab(self, parent):
        frame = ttk.Frame(parent, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        self.recommendations_text = tk.Text(
            frame,
            wrap='word',
            font=('Helvetica', 11),
            padx=10,
            pady=10,
            height=10,
            state='disabled'
        )
        self.recommendations_text.pack(fill=tk.BOTH, expand=True)
        
        # Configuration des tags
        self.recommendations_text.tag_configure('title', font=('Helvetica', 12, 'bold'))
        self.recommendations_text.tag_configure('important', foreground='#e74c3c', font=('Helvetica', 11, 'bold'))
        self.recommendations_text.tag_configure('normal', font=('Helvetica', 11))

    def verify_password(self):
        password = self.verify_pwd_entry.get().strip()
        if not password:
            self.show_message("Veuillez entrer un mot de passe à vérifier", "warning")
            return
        
        # Afficher l'état de chargement IMMÉDIATEMENT
        self.show_loading_state()
        self.root.update()  # Force la mise à jour de l'interface
        
        # Lancer l'analyse dans un thread séparé
        threading.Thread(
            target=self.perform_password_analysis,
            args=(password,),
            daemon=True
        ).start()

    def perform_password_analysis(self, password):
        try:
            # 1. Analyse locale (rapide)
            analysis = self.analyze_password_structure(password)
            
            # Mettre à jour l'interface avec les premiers résultats
            self.root.after(0, lambda: self.update_analysis_details(analysis))
            
            # 2. Vérification HIBP (réseau - potentiellement lent)
            hibp_result = self.check_hibp_status(password)
            
            # 3. Générer les recommandations
            recommendations = self.generate_recommendations(analysis, hibp_result)
            
            # 4. Calcul final du score
            score = self.calculate_security_score(analysis, hibp_result)
            
            # Mise à jour COMPLÈTE de l'interface
            self.root.after(0, lambda: self.display_results(
                analysis,
                hibp_result,
                recommendations,
                score
            ))
            
        except Exception as error:
            self.root.after(0, lambda: self.show_message(
                f"Erreur lors de l'analyse: {str(error)}",
                "error"
            ))

    def check_common_patterns(self, password):
        """Vérifie les motifs courants faibles dans les mots de passe"""
        common_patterns = [
            '123456', 'password', 'azerty', 'qwerty', 
            'abcdef', '654321', '111111', 'admin',
            'welcome', 'sunshine', 'letmein', '000000'
        ]
        password_lower = password.lower()
        return any(pattern in password_lower for pattern in common_patterns)

    def analyze_password_structure(self, password):
        """Analyse détaillée de la structure du mot de passe"""
        result = {
            'length': len(password),
            'has_lower': any(c.islower() for c in password),
            'has_upper': any(c.isupper() for c in password),
            'has_digit': any(c.isdigit() for c in password),
            'has_special': any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/" for c in password),
            'entropy': self.calculate_entropy(password),
            'common_patterns': self.check_common_patterns(password),
            'character_repetition': self.check_character_repetition(password),
            'keyboard_patterns': self.detect_keyboard_patterns(password)
        }
        
        # Calculer des métriques supplémentaires
        result['unique_chars'] = len(set(password))
        result['char_variety'] = sum([
            26 if result['has_lower'] else 0,
            26 if result['has_upper'] else 0,
            10 if result['has_digit'] else 0,
            32 if result['has_special'] else 0  # Approx. nombre de symboles courants
        ])
        
        return result

    def check_hibp_status(self, password):
        """Vérifie si le mot de passe a été compromis en utilisant le cache"""
        # Générer le hash SHA-1
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        
        # Vérifier le cache
        if prefix in self.hibp_cache:
            if suffix in self.hibp_cache[prefix]:
                return {'compromised': True, 'count': self.hibp_cache[prefix][suffix]}
            return {'compromised': False}
        
        try:
            # Requête à l'API HIBP
            response = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"User-Agent": "PasswordGeneratorApp"},
                timeout=10
            )
            
            if response.status_code == 200:
                # Mettre à jour le cache
                self.hibp_cache[prefix] = {}
                for line in response.text.splitlines():
                    parts = line.split(':')
                    self.hibp_cache[prefix][parts[0]] = int(parts[1])
                
                # Vérifier notre suffixe
                if suffix in self.hibp_cache[prefix]:
                    return {'compromised': True, 'count': self.hibp_cache[prefix][suffix]}
                
            return {'compromised': False}
        
        except Exception as e:
            print(f"Erreur HIBP: {str(e)}")
            return {'error': str(e)}

    def generate_recommendations(self, analysis, hibp_result):
        """Génère des recommandations personnalisées"""
        recommendations = []
        
        # Recommandations basées sur HIBP
        if hibp_result.get('compromised', False):
            recommendations.append((
                "CRITIQUE: Ce mot de passe a été compromis dans des fuites de données. "
                f"Il a été trouvé {hibp_result['count']} fois. Vous devez le changer immédiatement.",
                'danger'
            ))
        
        # Recommandations basées sur la longueur
        if analysis['length'] < 12:
            recommendations.append((
                f"Le mot de passe est trop court ({analysis['length']} caractères). "
                "Utilisez au moins 12 caractères.",
                'danger' if analysis['length'] < 8 else 'warning'
            ))
        
        # Recommandations basées sur la complexité
        missing = []
        if not analysis['has_lower']: missing.append("minuscules")
        if not analysis['has_upper']: missing.append("majuscules")
        if not analysis['has_digit']: missing.append("chiffres")
        if not analysis['has_special']: missing.append("symboles")
        
        if missing:
            recommendations.append((
                f"Le mot de passe ne contient pas de {', '.join(missing)}. "
                "Pour plus de sécurité, incluez différents types de caractères.",
                'warning'
            ))
        
        # Recommandations basées sur les motifs
        if analysis['common_patterns']:
            recommendations.append((
                "Motifs courants détectés (comme '123456', 'password', etc.). "
                "Évitez les séquences facilement devinables.",
                'danger'
            ))
        
        if analysis['character_repetition']:
            recommendations.append((
                "Répétition de caractères détectée. "
                "Évitez les répétitions comme 'aaa' ou '111'.",
                'warning'
            ))
        
        if analysis['keyboard_patterns']:
            recommendations.append((
                "Motifs clavier détectés (comme 'qwerty' ou 'azerty'). "
                "Ces motifs sont faciles à deviner.",
                'warning'
            ))
        
        # Recommandation d'entropie
        entropy = analysis['entropy']
        if entropy < 50:
            recommendations.append((
                f"Entropie faible ({entropy:.1f} bits). Le mot de passe pourrait être facilement bruteforcé.",
                'danger'
            ))
        elif entropy < 70:
            recommendations.append((
                f"Entropie modérée ({entropy:.1f} bits). Le mot de passe pourrait être plus fort.",
                'warning'
            ))
        
        # Si tout va bien
        if not recommendations and entropy >= 70:
            recommendations.append((
                "Excellent mot de passe! Conservez-le dans un gestionnaire de mots de passe sécurisé.",
                'good'
            ))
        
        return recommendations

    def calculate_security_score(self, analysis, hibp_result):
        """Calcule un score de sécurité entre 0 et 100"""
        score = 0
        
        # Pénalité si compromis
        if hibp_result.get('compromised', False):
            return 0
        
        # Points pour la longueur
        length = analysis['length']
        if length >= 16: score += 30
        elif length >= 12: score += 20
        elif length >= 8: score += 10
        
        # Points pour la variété de caractères
        variety = 0
        if analysis['has_lower']: variety += 1
        if analysis['has_upper']: variety += 1
        if analysis['has_digit']: variety += 1
        if analysis['has_special']: variety += 1
        
        score += variety * 10
        
        # Points pour l'entropie
        entropy = analysis['entropy']
        if entropy >= 80: score += 30
        elif entropy >= 60: score += 20
        elif entropy >= 40: score += 10
        
        # Pénalités pour les motifs faibles
        if analysis['common_patterns']: score -= 20
        if analysis['character_repetition']: score -= 15
        if analysis['keyboard_patterns']: score -= 10
        
        # Assurer que le score est entre 0 et 100
        return max(0, min(100, score))

    def display_results(self, analysis, hibp_result, recommendations, score):
        """Affiche les résultats dans l'interface"""
        # Mettre à jour le score global
        self.update_score_display(score)
        
        # Mettre à jour le statut HIBP
        self.update_hibp_status(hibp_result)
        
        # Mettre à jour l'analyse détaillée
        self.update_analysis_details(analysis)
        
        # Mettre à jour les recommandations
        self.update_recommendations(recommendations)
        
        # Sélectionner l'onglet Résumé par défaut
        self.result_notebook.select(0)

    def update_score_display(self, score):
        """Met à jour l'affichage du score"""
        self.score_meter['value'] = score
        
        if score >= 80:
            self.score_label.config(text="Excellent", foreground='#27ae60')
        elif score >= 60:
            self.score_label.config(text="Bon", foreground='#2ecc71')
        elif score >= 40:
            self.score_label.config(text="Moyen", foreground='#f39c12')
        elif score >= 20:
            self.score_label.config(text="Faible", foreground='#e67e22')
        else:
            self.score_label.config(text="Dangereux", foreground='#e74c3c')

    def update_hibp_status(self, result):
        """Met à jour le statut HIBP"""
        if result.get('error'):
            self.hibp_status_label.config(
                text=f"Erreur de vérification: {result['error']}",
                foreground='#e74c3c'
            )
        elif result.get('compromised', False):
            self.hibp_status_label.config(
                text=f"COMPROMIS - Trouvé {result['count']} fois dans des fuites",
                foreground='#e74c3c',
                font=('Helvetica', 12, 'bold')
            )
        else:
            self.hibp_status_label.config(
                text="Non trouvé dans les bases compromises",
                foreground='#27ae60'
            )

    def update_analysis_details(self, analysis):
        """Met à jour l'onglet d'analyse détaillée"""
        self.analysis_tree.delete(*self.analysis_tree.get_children())
        
        # Ajouter les données d'analyse
        self.add_analysis_row("Longueur", analysis['length'], self.get_length_status(analysis['length']))
        self.add_analysis_row("Entropie", f"{analysis['entropy']:.1f} bits", self.get_entropy_status(analysis['entropy']))
        self.add_analysis_row("Caractères uniques", analysis['unique_chars'], self.get_variety_status(analysis['unique_chars'], analysis['length']))
        
        # Types de caractères
        types = []
        if analysis['has_lower']: types.append("Minuscules")
        if analysis['has_upper']: types.append("Majuscules")
        if analysis['has_digit']: types.append("Chiffres")
        if analysis['has_special']: types.append("Symboles")
        
        self.add_analysis_row(
            "Types de caractères", 
            ', '.join(types) if types else "Aucun", 
            self.get_types_status(len(types))
        )
        
        # Problèmes détectés
        problems = []
        if analysis['common_patterns']: problems.append("Motifs courants")
        if analysis['character_repetition']: problems.append("Répétitions")
        if analysis['keyboard_patterns']: problems.append("Motifs clavier")
        
        self.add_analysis_row(
            "Problèmes détectés", 
            ', '.join(problems) if problems else "Aucun", 
            "danger" if problems else "good")

    def add_analysis_row(self, criteria, value, status):
        """Ajoute une ligne à l'analyse détaillée"""
        tag = ''
        if status == 'good': tag = 'good'
        elif status == 'warning': tag = 'warning'
        elif status == 'danger': tag = 'danger'
        
        self.analysis_tree.insert(
            '', 
            'end', 
            values=(criteria, status.upper(), value),
            tags=(tag,)
        )
        
        # Configurer les tags pour la couleur
        self.analysis_tree.tag_configure('good', foreground='#27ae60')
        self.analysis_tree.tag_configure('warning', foreground='#f39c12')
        self.analysis_tree.tag_configure('danger', foreground='#e74c3c')

    def update_recommendations(self, recommendations):
        """Met à jour l'onglet des recommandations"""
        self.recommendations_text.config(state='normal')
        self.recommendations_text.delete(1.0, tk.END)
        
        if not recommendations:
            self.recommendations_text.insert(tk.END, "Aucune recommandation - le mot de passe est sécurisé.", 'good')
            return
        
        self.recommendations_text.insert(tk.END, "Recommandations de sécurité:\n\n", 'title')
        
        for text, level in recommendations:
            tag = 'normal'
            if level == 'danger': tag = 'important'
            
            self.recommendations_text.insert(tk.END, "• ", 'normal')
            self.recommendations_text.insert(tk.END, text + "\n\n", tag)
        
        self.recommendations_text.config(state='disabled')

    def show_loading_state(self):
        """Affiche instantanément l'état de chargement"""
        self.score_label.config(text="Analyse en cours...", foreground='#3498db')
        self.score_meter['value'] = 50  # Barre à mi-chemin
        self.hibp_status_label.config(text="Vérification en cours...", foreground='#3498db')
        
        # Effacer les anciens résultats
        self.analysis_tree.delete(*self.analysis_tree.get_children())
        self.analysis_tree.insert('', 'end', values=("Veuillez patienter", "EN COURS", "..."))
        
        self.recommendations_text.config(state='normal')
        self.recommendations_text.delete(1.0, tk.END)
        self.recommendations_text.insert(tk.END, "Analyse en cours...")
        self.recommendations_text.config(state='disabled')
        
        # Forcer l'affichage immédiat
        self.result_notebook.select(0)  # Onglet Résumé
        self.root.update_idletasks()

    def show_message(self, message, level='info'):
        """Affiche un message à l'utilisateur"""
        if level == 'error':
            messagebox.showerror("Erreur", message)
        elif level == 'warning':
            messagebox.showwarning("Attention", message)
        else:
            messagebox.showinfo("Information", message)

    # Méthodes utilitaires pour l'analyse
    def get_length_status(self, length):
        if length >= 16: return 'good'
        elif length >= 12: return 'warning'
        return 'danger'

    def get_entropy_status(self, entropy):
        if entropy >= 70: return 'good'
        elif entropy >= 50: return 'warning'
        return 'danger'

    def get_variety_status(self, unique_chars, total_chars):
        ratio = unique_chars / total_chars
        if ratio >= 0.8: return 'good'
        elif ratio >= 0.6: return 'warning'
        return 'danger'

    def get_types_status(self, type_count):
        if type_count >= 4: return 'good'
        elif type_count >= 2: return 'warning'
        return 'danger'

    def detect_keyboard_patterns(self, password):
        """Détecte les motifs clavier courants"""
        patterns = [
            'qwerty', 'azerty', 'yxcvbn', '123456', 
            'password', 'azertyuiop', 'qsdfghjklm'
        ]
        password_lower = password.lower()
        return any(p in password_lower for p in patterns)
    

    def setup_attack_tab(self):
        frame = ttk.Frame(self.attack_tab, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        # Section saisie mot de passe
        input_frame = ttk.LabelFrame(frame, text="Mot de passe à tester", padding=10)
        input_frame.pack(fill=tk.X, pady=10)

        self.attack_pwd_entry = ttk.Entry(
            input_frame, 
            font=('Courier', 12),
            show="*",
            width=40
        )
        self.attack_pwd_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))

        # Bouton afficher/masquer
        self.show_attack_password = tk.BooleanVar(value=False)
        ttk.Button(
            input_frame, 
            text="👁", 
            width=3,
            command=lambda: self.toggle_password_visibility(
                self.attack_pwd_entry, 
                self.show_attack_password
            )
        ).pack(side=tk.LEFT)

        # Section sélection d'attaque - organisée en 2 colonnes
        attack_frame = ttk.LabelFrame(frame, text="Type d'attaque à simuler", padding=10)
        attack_frame.pack(fill=tk.X, pady=10)

        # Frame pour les colonnes
        columns_frame = ttk.Frame(attack_frame)
        columns_frame.pack(fill=tk.BOTH, expand=True)

        # Colonne de gauche
        left_column = ttk.Frame(columns_frame, padding=(0, 10, 0, 0))
        left_column.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Colonne de droite
        right_column = ttk.Frame(columns_frame)
        right_column.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.attack_type = tk.StringVar(value="bruteforce")
        
        # Liste des attaques réparties sur 2 colonnes
        attacks = [
            ("Force Brute Simple", "bruteforce"),
            ("Dictionnaire Classique", "dictionary"),
            ("Attaque par Motifs", "pattern"),
            ("Attaque Rainbow Table", "rainbow"),
            ("Attaque Hybride", "hybrid"),
            ("Credential Stuffing", "credstuff"),
            ("Password Spraying", "spray"),
            ("Analyse d'Entropie", "entropy")
        ]

        # Répartition des attaques dans les colonnes
        half = len(attacks) // 2 + len(attacks) % 2
        for i, (text, mode) in enumerate(attacks):
            column = left_column if i < half else right_column
            ttk.Radiobutton(
                column,
                text=text,
                variable=self.attack_type,
                value=mode
            ).pack(anchor='w', pady=2)

        # Frame pour les boutons côte à côte
        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=15)

        # Bouton lancer l'attaque
        ttk.Button(
            button_frame,
            text="⚡ Lancer le Test",
            command=self.run_attack_simulation
        ).pack(side=tk.LEFT, padx=5)

        # Bouton tout tester
        ttk.Button(
            button_frame,
            text="⚡ Tout Tester",
            command=self.run_all_attack_simulations
        ).pack(side=tk.LEFT, padx=5)

        # Résultats - avec plus d'espace et d'aération
        result_frame = ttk.LabelFrame(frame, text="Résultats des tests", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        self.attack_result = tk.Text(
            result_frame,
            height=12,
            wrap="word",
            state="disabled",
            font=('Helvetica', 10),
            padx=10,
            pady=10,
            spacing1=5,  # Espacement supplémentaire entre les lignes
            spacing2=2,  # Espacement entre les paragraphes
            spacing3=5   # Espacement après les blocs
        )
        self.attack_result.pack(fill=tk.BOTH, expand=True)

        # Configuration des tags pour la coloration et le style
        self.attack_result.tag_config("success", foreground="green")
        self.attack_result.tag_config("warning", foreground="orange")
        self.attack_result.tag_config("danger", foreground="red")
        self.attack_result.tag_config("bold", font=('Helvetica', 10, 'bold'))
        self.attack_result.tag_config("header", font=('Helvetica', 11, 'bold'), spacing1=10, spacing3=5)
        self.attack_result.tag_config("item", lmargin1=20, lmargin2=20, spacing1=3)

    def test_password_resistance(self):
        """Teste la résistance du mot de passe généré dans l'onglet Mot de Passe"""
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Attention", "Générez d'abord un mot de passe")
            return
        
        # Copier le mot de passe dans l'onglet de test
        self.attack_pwd_entry.delete(0, tk.END)
        self.attack_pwd_entry.insert(0, password)
        
        # Basculer vers l'onglet de test
        self.notebook.select(self.attack_tab)
        
        # Lancer tous les tests
        self.root.after(100, self.run_all_attack_simulations)


    def test_id_password_resistance(self):
        """Teste la résistance du mot de passe généré dans l'onglet ID + Mot de Passe"""
        password = self.id_pwd_entry.get()
        if not password:
            messagebox.showwarning("Attention", "Générez d'abord un mot de passe")
            return
        
        # Copier le mot de passe dans l'onglet de test
        self.attack_pwd_entry.delete(0, tk.END)
        self.attack_pwd_entry.insert(0, password)
        
        # Basculer vers l'onglet de test
        self.notebook.select(self.attack_tab)
        
        # Lancer tous les tests
        self.root.after(100, self.run_all_attack_simulations)


    def run_attack_simulation(self):
        """Lance la simulation d'attaque sélectionnée"""
        password = self.attack_pwd_entry.get()
        if not password:
            messagebox.showwarning("Erreur", "Veuillez entrer un mot de passe à tester")
            return
        
        attack_type = self.attack_type.get()
        
        # Afficher le chargement
        self.attack_result.config(state="normal")
        self.attack_result.delete(1.0, tk.END)
        self.attack_result.insert(tk.END, f"Simulation d'attaque {attack_type} en cours...\n")
        self.attack_result.config(state="disabled")
        self.root.update()  # Forcer la mise à jour
        
        # Lancer dans un thread séparé
        threading.Thread(
            target=self.simulate_attack,
            args=(password, attack_type),
            daemon=True
        ).start()


    def simulate_attack(self, password, attack_type):
        """Simule l'attaque en arrière-plan"""
        try:
            result = ""
            start_time = time.time()
            
            if attack_type == "bruteforce":
                result = self.simulate_bruteforce(password)
            elif attack_type == "dictionary":
                result = self.simulate_dictionary(password)
            elif attack_type == "pattern":
                result = self.simulate_pattern_attack(password)
            elif attack_type == "rainbow":
                result = self.simulate_rainbow(password)
            elif attack_type == "social":
                result = self.simulate_social_engineering(password)
            elif attack_type == "hybrid":
                result = self.simulate_hybrid_attack(password)
            elif attack_type == "credstuff":
                result = self.simulate_credential_stuffing(password)
            elif attack_type == "spray":
                result = self.simulate_password_spraying(password)
            elif attack_type == "entropy":
                result = self.simulate_entropy_analysis(password)
                
            elapsed = time.time() - start_time
            
            # Mise à jour de l'interface
            self.root.after(0, lambda: self.display_attack_result(
                password, 
                attack_type,
                result,
                elapsed
            ))
            
        except Exception as error:
            self.root.after(0, lambda err=error: self.show_attack_error(str(err)))


    def display_attack_result(self, password, attack_type, result, elapsed_time):
        """Affiche les résultats de l'attaque"""
        self.attack_result.config(state="normal")
        self.attack_result.delete(1.0, tk.END)
        
        # Titre
        attack_names = {
            "bruteforce": "Force Brute Simple",
            "dictionary": "Dictionnaire Classique",
            "pattern": "Attaque par Motifs",
            "rainbow": "Attaque Rainbow Table",
            "social": "Ingénierie Sociale",
            "hybrid": "Attaque Hybride",
            "credstuff": "Credential Stuffing",
            "spray": "Password Spraying",
            "entropy": "Analyse d'Entropie"
        }
        
        self.attack_result.insert(tk.END, f"Résultats du test: {attack_names.get(attack_type, attack_type)}\n", "bold")
        self.attack_result.insert(tk.END, f"- Mot de passe testé: {password}\n")
        self.attack_result.insert(tk.END, f"- Temps d'analyse: {elapsed_time:.2f}s\n\n")
        
        # Affichage spécifique pour chaque type d'attaque
        if attack_type == "entropy":
            self.attack_result.insert(tk.END, f"Entropie: {result['entropy']:.1f} bits\n")
            self.attack_result.insert(tk.END, f"Niveau de sécurité: {result['status']}\n")
            
            if result["vulnerable"]:
                self.attack_result.insert(tk.END, "❌ Entropie trop faible!\n", "danger")
                self.attack_result.insert(tk.END, f"Raison: {result['reason']}\n")
            else:
                self.attack_result.insert(tk.END, "✅ Entropie suffisante\n", "success")
        else:
            if result["vulnerable"]:
                self.attack_result.insert(tk.END, "❌ VULNÉRABLE À CETTE ATTAQUE\n", "danger")
                self.attack_result.insert(tk.END, f"Raison: {result['reason']}\n")
            else:
                self.attack_result.insert(tk.END, "✅ RÉSISTANT À CETTE ATTAQUE\n", "success")
                self.attack_result.insert(tk.END, f"{result['strength']}\n")
        
        # Recommandations générales
        self.attack_result.insert(tk.END, "\nRecommandations:\n", "bold")
        if len(password) < 12:
            self.attack_result.insert(tk.END, "- Utilisez un mot de passe plus long (au moins 12 caractères)\n")
        if not any(c.isupper() for c in password) or not any(c.islower() for c in password):
            self.attack_result.insert(tk.END, "- Mélangez majuscules et minuscules\n")
        if not any(c.isdigit() for c in password):
            self.attack_result.insert(tk.END, "- Ajoutez des chiffres\n")
        if not any(c in "!@#$%^&*" for c in password):
            self.attack_result.insert(tk.END, "- Ajoutez des caractères spéciaux\n")
        
        self.attack_result.config(state="disabled")

    
    def simulate_bruteforce(self, password):
        """Simule une attaque par force brute"""
        length = len(password)
        charset = 0
        
        # Calcul de la complexité
        if any(c.islower() for c in password): charset += 26
        if any(c.isupper() for c in password): charset += 26
        if any(c.isdigit() for c in password): charset += 10
        if any(c in "!@#$%^&*" for c in password): charset += 32
        
        # Estimation du temps (simplifiée)
        entropy = length * math.log2(charset) if charset else 0
        time_to_crack = (2 ** entropy) / (1e9 * 1000)  # Hypothèse: 1 milliard de tentatives/s
        
        return {
            "vulnerable": time_to_crack < 86400,  # Moins d'un jour
            "reason": f"Temps estimé: {time_to_crack:.2f} secondes" if time_to_crack < 86400 else None,
            "strength": f"Temps de crack estimé: {time_to_crack:.2e} secondes"
        }

    def simulate_dictionary(self, password):
        """Simule une attaque par dictionnaire"""
        common_passwords = [
            "password", "123456", "qwerty", "azerty", 
            "admin", "welcome", "sunshine", "letmein"
        ]
        
        return {
            "vulnerable": password.lower() in common_passwords,
            "reason": "Trouvé dans les mots de passe courants" if password.lower() in common_passwords else None,
            "strength": "Absent des dictionnaires courants"
        }

    def simulate_pattern_attack(self, password):
        """Simule une attaque par motifs"""
        patterns = [
            r'1234\d*', r'qwerty.*', r'azerty.*', 
            r'\d{6}', r'[a-z]{2}\d{4}', r'\d{2}[a-z]{2}\d{2}'
        ]
        
        for pattern in patterns:
            if re.fullmatch(pattern, password.lower()):
                return {
                    "vulnerable": True,
                    "reason": f"Correspond au motif: {pattern}",
                    "strength": None
                }
        
        return {
            "vulnerable": False,
            "reason": None,
            "strength": "Aucun motif vulnérable détecté"
        }
    
    def simulate_rainbow(self, password):
        """Simule une attaque par rainbow table"""
        # Simulation simplifiée
        return {
            "vulnerable": len(password) < 12 and not any(c in "!@#$%" for c in password),
            "reason": "Trop court et pas de caractères spéciaux" if len(password) < 12 else None,
            "strength": "Résistant aux rainbow tables (longueur + complexité)"
        }

    def simulate_hybrid_attack(self, password):
        """Simule une attaque hybride (dictionnaire + variations)"""
        common_words = ["password", "123456", "azerty", "qwerty", "admin", "welcome"]
        variations = [
            password.lower(),
            password.lower() + "123",
            password.lower() + "!",
            password.lower().capitalize(),
            password.lower().replace('a', '@').replace('e', '3')
        ]
        
        for variant in variations:
            if variant in common_words or any(word in variant for word in common_words):
                return {
                    "vulnerable": True,
                    "reason": "Motif faible détecté avec variations communes",
                    "strength": None
                }
        
        return {
            "vulnerable": False,
            "reason": None,
            "strength": "Résistant aux attaques hybrides"
        }

    def simulate_credential_stuffing(self, password):
        """Simule une attaque par credential stuffing"""
        # En réalité, on vérifierait contre une base de données de fuites
        # Ici on simule avec quelques mots de passe courants
        common_passwords = ["password123", "azerty123", "qwerty123", "welcome1"]
        
        return {
            "vulnerable": password in common_passwords,
            "reason": "Mot de passe trouvé dans des fuites connues" if password in common_passwords else None,
            "strength": "Non trouvé dans les bases de données de fuites courantes"
        }

    def simulate_password_spraying(self, password):
        """Simule une attaque par spray de mots de passe"""
        # Liste de mots de passe fréquemment utilisés dans les attaques par spray
        spray_passwords = [
            "Winter2023!", "Spring2023!", "Summer2023!", "Autumn2023!",
            "Password1", "Welcome1", "Company123", "Admin123"
        ]
        
        return {
            "vulnerable": password in spray_passwords,
            "reason": "Mot de passe couramment utilisé dans les attaques par spray" if password in spray_passwords else None,
            "strength": "Non vulnérable aux attaques par spray"
        }

    def simulate_entropy_analysis(self, password):
        """Analyse l'entropie du mot de passe"""
        entropy = self.calculate_entropy(password)
        
        if entropy < 50:
            status = "Très faible"
        elif entropy < 70:
            status = "Faible"
        elif entropy < 100:
            status = "Moyenne"
        else:
            status = "Forte"
        
        return {
            "entropy": entropy,
            "status": status,
            "vulnerable": entropy < 70,
            "reason": f"Entropie trop faible ({entropy:.1f} bits)" if entropy < 70 else None,
            "strength": f"Entropie {status} ({entropy:.1f} bits)"
        }
    
    def run_all_attack_simulations(self):
        """Lance toutes les simulations d'attaque"""
        password = self.attack_pwd_entry.get()
        if not password:
            messagebox.showwarning("Erreur", "Veuillez entrer un mot de passe à tester")
            return
        
        self.attack_result.config(state="normal")
        self.attack_result.delete(1.0, tk.END)
        self.attack_result.insert(tk.END, "Lancement de toutes les simulations...\n\n")
        self.attack_result.config(state="disabled")
        self.root.update()
        
        attacks = [
            ("Force Brute", "bruteforce"),
            ("Dictionnaire", "dictionary"),
            ("Motifs", "pattern"),
            ("Rainbow Table", "rainbow"),
            ("Hybride", "hybrid"),
            ("Credential Stuffing", "credstuff"),
            ("Password Spraying", "spray"),
            ("Analyse d'Entropie", "entropy")
        ]
        
        def worker():
            results = []
            for name, attack_type in attacks:
                try:
                    if attack_type == "bruteforce":
                        result = self.simulate_bruteforce(password)
                    elif attack_type == "dictionary":
                        result = self.simulate_dictionary(password)
                    elif attack_type == "pattern":
                        result = self.simulate_pattern_attack(password)
                    elif attack_type == "rainbow":
                        result = self.simulate_rainbow(password)
                    elif attack_type == "hybrid":
                        result = self.simulate_hybrid_attack(password)
                    elif attack_type == "credstuff":
                        result = self.simulate_credential_stuffing(password)
                    elif attack_type == "spray":
                        result = self.simulate_password_spraying(password)
                    elif attack_type == "entropy":
                        result = self.simulate_entropy_analysis(password)
                    
                    results.append((name, result))
                except Exception as e:
                    results.append((name, {"error": str(e)}))
            
            self.root.after(0, lambda: self.display_all_attack_results(password, results))
        
        threading.Thread(target=worker, daemon=True).start()

    def display_all_attack_results(self, password, results):
        """Affiche les résultats de toutes les attaques"""
        self.attack_result.config(state="normal")
        self.attack_result.delete(1.0, tk.END)
        
        self.attack_result.insert(tk.END, f"Résultats des tests pour: {password}\n\n", "bold")
        
        vulnerable_count = 0
        for name, result in results:
            if "error" in result:
                self.attack_result.insert(tk.END, f"{name}: Erreur - {result['error']}\n", "danger")
                continue
            
            if result.get("vulnerable", False):
                vulnerable_count += 1
                self.attack_result.insert(tk.END, f"❌ {name}: Vulnérable\n", "danger")
                self.attack_result.insert(tk.END, f"   Raison: {result.get('reason', 'Non spécifié')}\n")
            else:
                self.attack_result.insert(tk.END, f"✅ {name}: Sécurisé\n", "success")
                if "strength" in result:
                    self.attack_result.insert(tk.END, f"   {result['strength']}\n")
        
        # Résumé
        self.attack_result.insert(tk.END, f"\nRésumé: {vulnerable_count} vulnérabilité(s) trouvée(s) sur {len(results)} tests\n", "bold")
        if vulnerable_count == 0:
            self.attack_result.insert(tk.END, "Votre mot de passe semble robuste contre toutes les attaques testées!", "success")
        else:
            self.attack_result.insert(tk.END, "Votre mot de passe présente des vulnérabilités. Veuillez choisir un autre mot de passe.", "danger")
        
        self.attack_result.config(state="disabled")

    def show_attack_error(self, message):
        """Affiche les erreurs d'attaque"""
        self.attack_result.config(state="normal")
        self.attack_result.delete(1.0, tk.END)
        self.attack_result.insert(tk.END, f"Erreur lors de la simulation:\n{message}", "danger")
        self.attack_result.config(state="disabled")

if __name__ == "__main__":
    root = tk.Tk()
    app = VaultGenApp(root)
    root.mainloop()