import pyperclip
import streamlit as st
import secrets
import string
import hashlib
import requests
import re
import math
from io import BytesIO
from collections import defaultdict

# Configuration de la page
st.set_page_config(
    page_title="🔐 VAULTGEN",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Styles CSS personnalisés
st.markdown("""
<style>
    /* Style pour la sidebar */
    [data-testid="stSidebar"] {
        background-color: #f8f9fa;
        padding: 1.5rem 1rem;
    }
    
    /* Style pour le titre VAULTGEN */
    .vaultgen-header {
        font-size: 1.8rem;
        font-weight: 700;
        color: #2c3e50;
        margin-bottom: 2rem;
        text-align: center;
        padding-bottom: 0.5rem;
        border-bottom: 2px solid #2c3e50;
    }
    
    /* Style pour les options de navigation */
    .nav-option {
        padding: 0.8rem 1rem;
        margin: 0.3rem 0;
        border-radius: 8px;
        transition: all 0.3s ease;
        font-size: 1rem;
        text-align: center;
    }
    
    .nav-option:hover {
        background-color: #e9ecef;
    }
    
    .nav-option.selected {
        background-color: #2c3e50;
        color: white !important;
        font-weight: 500;
    }
    
    /* Espacement entre les sections */
    .nav-section {
        margin: 1.5rem 0 0.5rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Navigation - Remplacez la partie existante
with st.sidebar:
    # En-tête VAULTGEN avec description juste en dessous
    st.markdown('''
    <div class="vaultgen-header">🔐 VAULTGEN</div>
    ''', unsafe_allow_html=True)
    
    # Options de navigation
    tabs = [
        {"name": "Mot de Passe", "icon": "🔑"},
        {"name": "ID + Mot de Passe", "icon": "🆔"},
        {"name": "Vérification", "icon": "🔍"}, 
        {"name": "Test de Résistance", "icon": "⚡"}
    ]
    
    selected_tab = st.session_state.get("selected_tab", "Mot de Passe")
    
    for tab in tabs:
        if st.button(
            f"{tab['icon']} {tab['name']}",
            key=f"nav_{tab['name']}",
            use_container_width=True,
            type="primary" if selected_tab == tab['name'] else "secondary"
        ):
            st.session_state.selected_tab = tab['name']
            st.rerun()
    

# Fonctions utilitaires
def is_valid_email(email):
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


class PasswordGenerator:
    # Init Class Password Generator
    def __init__(self):
        self.hibp_cache = defaultdict(dict)
        self.common_passwords = self.load_password_dictionary()
        st.session_state['dict_loaded'] = True
        
    def generate_personal_password(self, base_words, length=16, use_upper=True, use_digits=True, use_symbols=True, exclude_ambiguous=False):
        """Transforme des mots personnels en mot de passe sécurisé"""
        if length < 12:
            length = 12
        elif length > 64:
            length = 64
            
        if not base_words or len(base_words) < 2:
            raise ValueError("Au moins 2 mots requis")

        chars = []
        ambiguous_chars = "lI1O0|"
        
        lower_chars = string.ascii_lowercase
        if exclude_ambiguous:
            lower_chars = ''.join(c for c in lower_chars if c not in ambiguous_chars)
        chars.extend(list(lower_chars))
        
        if use_upper:
            upper_chars = string.ascii_uppercase
            if exclude_ambiguous:
                upper_chars = ''.join(c for c in upper_chars if c not in ambiguous_chars)
            chars.extend(list(upper_chars))
        
        if use_digits:
            digit_chars = string.digits
            if exclude_ambiguous:
                digit_chars = ''.join(c for c in digit_chars if c not in ambiguous_chars)
            chars.extend(list(digit_chars))
        
        if use_symbols:
            symbol_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?/"
            if exclude_ambiguous:
                symbol_chars = ''.join(c for c in symbol_chars if c not in ambiguous_chars)
            chars.extend(list(symbol_chars))

        processed = []
        for word in base_words:
            word = word.strip()
            if not word:
                continue
                
            variations = [
                word,
                word.capitalize(),
                word.upper(),
                word + (secrets.choice(symbol_chars) if use_symbols else str(secrets.SystemRandom().randint(0, 9))),
                word.translate(str.maketrans('eao', '340')) + str(secrets.SystemRandom().randint(10, 99)),
                ''.join(secrets.choice([c.upper(), c]) for c in word),
                word[:len(word)//2] + (secrets.choice(symbol_chars) if use_symbols else str(secrets.SystemRandom().randint(0, 9))) + word[len(word)//2:]
            ]
            
            processed.append(secrets.choice(variations))
        
        secrets.SystemRandom().shuffle(processed)
        base = ''.join(processed)
        
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
        
        while len(base) < length:
            base += secrets.choice(chars)
        
        password = list(base)
        for _ in range(3):
            secrets.SystemRandom().shuffle(password)
        
        final_pwd = ''.join(password)[:length]
        
        return final_pwd

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

        secrets.SystemRandom().shuffle(password)
        return "".join(password)


    def create_readable_version(self, password):
        # Dictionnaire de substitutions pour les caractères spéciaux
        special_char_map = {
            '!': 'i',
            '@': 'a',
            '#': 'h',
            '$': 's',
            '%': 'p',
            '^': 'v',
            '&': 'n',
            '*': 'x',
            '(': 'c',
            ')': 'd',
            '-': '_',
            '_': '-',
            '=': 'e',
            '+': 't',
            '[': 'b',
            ']': 'k',
            '{': 'f',
            '}': 'g',
            '|': 'l',
            ';': 'j',
            ':': 'i',
            ',': 'm',
            '.': 'o',
            '<': 'c',
            '>': 'd',
            '?': 'w',
            '/': 'v',
            '~': 'n',
            '`': 'a'
        }
        
        # Convertir les chiffres en mots
        digit_map = {
            '0': 'zero',
            '1': 'un',
            '2': 'deux',
            '3': 'trois',
            '4': 'quatre',
            '5': 'cinq',
            '6': 'six',
            '7': 'sept',
            '8': 'huit',
            '9': 'neuf'
        }
        
        readable_parts = []
        for char in password:
            if char in special_char_map:
                readable_parts.append(f"[{special_char_map[char]}]")
            elif char.isdigit():
                readable_parts.append(digit_map[char])
            else:
                readable_parts.append(char)
        
        # Créer des groupes de 4 caractères séparés par des espaces
        grouped = []
        for i in range(0, len(readable_parts), 4):
            group = ''.join(readable_parts[i:i+4])
            grouped.append(group)
        
        return ' '.join(grouped)
    

    def calculate_entropy(self, password):
        charset = 0
        # Minuscules
        if any(c.islower() for c in password): 
            charset += 26
        # Majuscules
        if any(c.isupper() for c in password): 
            charset += 26
        # Chiffres
        if any(c.isdigit() for c in password): 
            charset += 10
        # Symboles étendus
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?/~"
        if any(c in symbols for c in password):
            charset += len(symbols)
        
        length = len(password)
        entropy = length * math.log2(charset) if charset else 0
        
        # Pénalité pour répétitions
        repeats = sum(1 for i in range(length-1) if password[i] == password[i+1])
        entropy -= repeats * 0.5
        
        return max(0, entropy)


    def evaluate_password_strength(self, password):
        analysis = self.analyze_password_structure(password)
        hibp_result = self.check_hibp_status(password)
        
        # Critères stricts
        length_ok = analysis['length'] >= 14
        variety_ok = (analysis['has_lower'] and 
                    analysis['has_upper'] and 
                    analysis['has_digit'] and 
                    analysis['has_special'])
        entropy_ok = analysis['entropy'] >= 90
        not_compromised = not hibp_result.get('compromised', False)
        no_patterns = not (analysis['common_patterns'] or 
                        analysis['keyboard_patterns'])
        
        # Score sur 100
        score = 0
        if length_ok: score += 25
        if variety_ok: score += 25 
        if entropy_ok: score += 30
        if not_compromised: score += 10
        if no_patterns: score += 10
        
        # Ajustements finaux
        if analysis['length'] >= 18: score += 5
        if analysis['entropy'] >= 120: score += 5
        if analysis['unique_chars']/analysis['length'] >= 0.9: score += 5
        
        return min(100, score), analysis

    def check_common_patterns(self, password):
        common_patterns = [
            '123456', 'password', 'azerty', 'qwerty', 
            'abcdef', '654321', '111111', 'admin',
            'welcome', 'sunshine', 'letmein', '000000'
        ]
        password_lower = password.lower()
        return any(pattern in password_lower for pattern in common_patterns)

    def check_character_repetition(self, password):
        return bool(re.search(r'(.)\1{2,}', password))

    def detect_keyboard_patterns(self, password):
        patterns = [
            'qwerty', 'azerty', 'yxcvbn', '123456', 
            'password', 'azertyuiop', 'qsdfghjklm'
        ]
        password_lower = password.lower()
        return any(p in password_lower for p in patterns)

    def analyze_password_structure(self, password):
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
        
        result['unique_chars'] = len(set(password))
        result['char_variety'] = sum([
            26 if result['has_lower'] else 0,
            26 if result['has_upper'] else 0,
            10 if result['has_digit'] else 0,
            32 if result['has_special'] else 0
        ])
        
        return result

    def check_hibp_status(self, password):
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        
        if prefix in self.hibp_cache:
            if suffix in self.hibp_cache[prefix]:
                return {'compromised': True, 'count': self.hibp_cache[prefix][suffix]}
            return {'compromised': False}
        
        try:
            response = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"User-Agent": "PasswordGeneratorApp"},
                timeout=10
            )
            
            if response.status_code == 200:
                self.hibp_cache[prefix] = {}
                for line in response.text.splitlines():
                    parts = line.split(':')
                    self.hibp_cache[prefix][parts[0]] = int(parts[1])
                
                if suffix in self.hibp_cache[prefix]:
                    return {'compromised': True, 'count': self.hibp_cache[prefix][suffix]}
                
            return {'compromised': False}
        
        except Exception as e:
            print(f"Erreur HIBP: {str(e)}")
            return {'error': str(e)}


    def get_length_status(self, length):
        """Détermine le statut de sécurité basé sur la longueur"""
        if length >= 16: return 'good'
        elif length >= 12: return 'warning'
        return 'danger'

    def get_entropy_status(self, entropy):
        """Détermine le statut de sécurité basé sur l'entropie"""
        if entropy >= 70: return 'good'
        elif entropy >= 50: return 'warning'
        return 'danger'

    def get_variety_status(self, unique_chars, total_chars):
        """Détermine le statut de sécurité basé sur la variété de caractères"""
        ratio = unique_chars / total_chars
        if ratio >= 0.8: return 'good'
        elif ratio >= 0.6: return 'warning'
        return 'danger'

    def get_types_status(self, type_count):
        """Détermine le statut de sécurité basé sur le nombre de types de caractères"""
        if type_count >= 4: return 'good'
        elif type_count >= 2: return 'warning'
        return 'danger'

    def is_high_security(self, password):
        score, _ = self.evaluate_password_strength(password)
        return score >= 90

    def simulate_bruteforce(self, password):
        entropy = self.calculate_entropy(password)
        time_to_crack = (2 ** entropy) / (1e12 * 1000)  # Hypothèse: 1 trillion de tentatives/s
        
        vulnerable = time_to_crack < 31536000  # 1 an en secondes
        
        return {
            "vulnerable": vulnerable,
            "reason": f"Temps de crack estimé: {time_to_crack:.1e} secondes" if vulnerable else None,
            "strength": None if vulnerable else f"Résistant (>{time_to_crack:.1e} secondes)"
        }
    

    def generate_common_variations(self, password_list):
        variations = set()
        common_subs = {
            'a': ['@', '4'],
            'e': ['3'],
            'i': ['1', '!'],
            'o': ['0'],
            's': ['$', '5']
        }
        
        for pwd in password_list:
            # Ajouter le mot original
            variations.add(pwd)
            
            # Ajouter des versions majuscules/minuscules
            variations.add(pwd.lower())
            variations.add(pwd.upper())
            variations.add(pwd.capitalize())
            
            # Ajouter des suffixes courants
            for suffix in ['123', '!', '?', '2023', '1234', '1']:
                variations.add(pwd + suffix)
            
            # Ajouter des substitutions
            for char, subs in common_subs.items():
                if char in pwd:
                    for sub in subs:
                        variations.add(pwd.replace(char, sub))
        
        return variations
    

    def load_password_dictionary(self):
        try:
            with open('dict.txt', 'r', encoding='utf-8', errors='ignore') as f:
                # Utilise un set pour des recherches plus rapides
                return {line.strip() for line in f if line.strip()}
        except FileNotFoundError:
            st.warning("Fichier dictionnaire.txt non trouvé - utilisation des valeurs par défaut")
            return {
                'password', '123456', 'qwerty', 'azerty',
                'admin', 'welcome', 'sunshine', 'letmein'
            }

    def simulate_dictionary(self, password):
        password_lower = password.lower()
        
        # Vérification directe
        if password_lower in self.common_passwords:
            return {
                "vulnerable": True,
                "reason": "Mot de passe trouvé dans le dictionnaire",
                "strength": None
            }
        
        # Vérification des parties (n-grams)
        for i in range(len(password_lower)-3):
            substring = password_lower[i:i+4]
            if substring in self.common_passwords:
                return {
                    "vulnerable": True,
                    "reason": f"Contient une séquence vulnérable: {substring}",
                    "strength": None
                }
        
        # Vérification des substitutions
        simple_subs = {'@':'a', '4':'a', '3':'e', '1':'i', '0':'o', '$':'s'}
        substituted = ''.join([simple_subs.get(c, c) for c in password_lower])
        if substituted in self.common_passwords:
            return {
                "vulnerable": True,
                "reason": "Variation d'un mot de passe commun",
                "strength": None
            }
        
        return {
            "vulnerable": False,
            "reason": None,
            "strength": "Résistant aux attaques par dictionnaire"
        }


    def simulate_pattern_attack(self, password):
        """Simule une attaque par reconnaissance de motifs"""
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
        return {
            "vulnerable": len(password) < 12 and not any(c in "!@#$%" for c in password),
            "reason": "Trop court et pas de caractères spéciaux" if len(password) < 12 else None,
            "strength": "Résistant aux rainbow tables (longueur + complexité)"
        }

    def simulate_hybrid_attack(self, password):
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
        common_passwords = ["password123", "azerty123", "qwerty123", "welcome1"]
        
        return {
            "vulnerable": password in common_passwords,
            "reason": "Mot de passe trouvé dans des fuites connues" if password in common_passwords else None,
            "strength": "Non trouvé dans les bases de données de fuites courantes"
        }

    def simulate_password_spraying(self, password):
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
    

    def simulate_hybrid(self, password):
        """Simule une attaque hybride (combinaison de dictionnaire et de force brute)"""
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

    def simulate_credstuff(self, password):
        """Simule une attaque par credential stuffing (réutilisation de mots de passe fuits)"""
        common_passwords = ["password123", "azerty123", "qwerty123", "welcome1"]
        
        return {
            "vulnerable": password in common_passwords,
            "reason": "Mot de passe trouvé dans des fuites connues" if password in common_passwords else None,
            "strength": "Non trouvé dans les bases de données de fuites courantes"
        }

    def simulate_spray(self, password):
        """Simule une attaque par password spraying (essai de mots de passe courants)"""
        spray_passwords = [
            "Winter2023!", "Spring2023!", "Summer2023!", "Autumn2023!",
            "Password1", "Welcome1", "Company123", "Admin123"
        ]
        
        return {
            "vulnerable": password in spray_passwords,
            "reason": "Mot de passe couramment utilisé dans les attaques par spray" if password in spray_passwords else None,
            "strength": "Non vulnérable aux attaques par spray"
        }

    def simulate_entropy(self, password):
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


    def display_attack_results(self, results, attack_types, full_test=False):
        vulnerable_count = sum(1 for _, r in results if r.get("vulnerable", False))
        
        # Création des onglets
        tab1, tab2 = st.tabs(["Résultats détaillés", "Résumé et conseils"])
        
        with tab1:
            st.subheader("Résultats des Tests")
            
            for item in results:
                attack_type, result = item
                name = attack_type if full_test else next(n for n, t in attack_types if t == attack_type)
                
                # Badge de statut
                if "error" in result:
                    badge = ":red[**ERREUR**]"
                elif result.get("vulnerable", False):
                    badge = ":red[**VULNÉRABLE**]"
                else:
                    badge = ":green[**SÉCURISÉ**]"
                
                st.markdown(f"##### {name} - {badge}")
                
                if "error" in result:
                    st.error(result["error"], icon="⚠️")
                elif result.get("vulnerable", False):
                    st.error(f"**Raison:** {result.get('reason', 'Non spécifiée')}", icon="❌")
                else:
                    st.success(result.get("strength", "Aucune vulnérabilité détectée"), icon="✅")
                
                st.divider()
        
        with tab2:
            st.subheader("Synthèse des résultats")
            
            # Score visuel
            score = 100 - (vulnerable_count * 100 / len(results))
            st.metric("Score de résistance", f"{score:.0f}/100")
            st.progress(score/100)
            
            # Résumé des vulnérabilités
            st.subheader("Vulnérabilités détectées")
            if vulnerable_count == 0:
                st.success("✅ Aucune vulnérabilité trouvée")
            else:
                st.error(f"❌ {vulnerable_count} vulnérabilité(s) détectée(s)")
            
            # Conseils personnalisés
            st.subheader("Recommandations")
            if vulnerable_count == 0:
                st.success("Votre mot de passe est excellent. Conservez-le dans un gestionnaire sécurisé.")
            elif vulnerable_count <= 2:
                st.warning("""
                Votre mot de passe présente quelques faiblesses :
                - Augmentez sa longueur
                - Ajoutez des caractères spéciaux
                - Évitez les motifs reconnaissables
                """)
            else:
                st.error("""
                Votre mot de passe est vulnérable à plusieurs attaques :
                - Changez-le immédiatement
                - Utilisez notre générateur pour en créer un nouveau
                - Ne réutilisez pas ce mot de passe ailleurs
                """)
            
            # Bouton pour générer un nouveau mot de passe
            if vulnerable_count > 0:
                def redirect_to_generator():
                    st.session_state.selected_tab = "Mot de Passe"

                if st.button("🔄 Générer un nouveau mot de passe sécurisé", 
                            on_click=redirect_to_generator):
                    st.rerun()
                

# Initialisation de l'application
generator = PasswordGenerator()


if st.session_state.get("selected_tab", "Mot de Passe") == "Mot de Passe":
    st.title("🔐 Générateur de Mot de Passe")
    
    with st.expander("Configuration", expanded=True):
        col1, col2 = st.columns(2)
        
        with col1:
            generation_mode = st.radio(
                "Type de génération",
                ["Mot de passe classique", "Passphrase"],
                horizontal=True
            )
        
        if generation_mode == "Mot de passe classique":
            with st.container():
                col1, col2 = st.columns(2)
                
                with col1:
                    pwd_length = st.slider("Longueur (12-64)", 12, 64, 16)
                    pwd_upper = st.checkbox("Majuscules (A-Z)", value=True)
                    pwd_digits = st.checkbox("Chiffres (0-9)", value=True)
                
                with col2:
                    pwd_symbols = st.checkbox("Symboles (!@#)", value=True)
                    pwd_ambiguous = st.checkbox("Exclure caractères ambigus", value=False)
        
        else:
            custom_words = st.text_input(
                "Mots clés personnels (séparés par des virgules)",
                "exemple,chien,anniversaire,ville"
            )
            
            with st.container():
                col1, col2 = st.columns(2)
                
                with col1:
                    passphrase_length = st.slider("Longueur (12-64)", 12, 64, 16)
                    passphrase_upper = st.checkbox("Majuscules (A-Z)", value=True)
                    passphrase_digits = st.checkbox("Chiffres (0-9)", value=True)
                
                with col2:
                    passphrase_symbols = st.checkbox("Symboles (!@#)", value=True)
                    passphrase_ambiguous = st.checkbox("Exclure caractères ambigus", value=False)
    
    if st.button("🎲 Générer", use_container_width=True):
        if generation_mode == "Mot de passe classique":
            password = generator.generate_password(
                pwd_length,
                pwd_upper,
                pwd_digits,
                pwd_symbols,
                pwd_ambiguous
            )
            is_passphrase = False
        else:
            base_words = [w.strip() for w in custom_words.split(",") if w.strip()]
            if not base_words:
                st.warning("Veuillez entrer des mots personnels séparés par des virgules")
                st.stop()
            
            password = generator.generate_personal_password(
                base_words=base_words,
                length=passphrase_length,
                use_upper=passphrase_upper,
                use_digits=passphrase_digits,
                use_symbols=passphrase_symbols,
                exclude_ambiguous=passphrase_ambiguous
            )
            is_passphrase = True
        
        st.session_state.password = password
        st.session_state.is_passphrase = is_passphrase
    
    if "password" in st.session_state:
        with st.container():
            # Première ligne : Checkbox + Champ mot de passe
            col1, col2 = st.columns([1, 4])
            with col1:
                show_pwd = st.checkbox("Afficher", key="main_pwd_checkbox")
            with col2:
                st.text_input(
                    "Mot de passe généré",
                    value=st.session_state.password,
                    type="default" if show_pwd else "password",
                    key="main_pwd_display",
                    label_visibility="collapsed"
                )

            # Ajout de la version lisible
            if st.checkbox("Afficher version lisible", key="show_readable"):
                readable_version = generator.create_readable_version(st.session_state.password)
                st.text_area(
                    "Version lisible",
                    value=readable_version,
                    key="readable_display",
                    height=70
                )
                if st.button("📋 Copier"):
                    st.session_state.copied_text = st.session_state.password  
                    st.code(st.session_state.copied_text, language="text") 
                    st.toast("Sélectionnez le texte ci-dessus et copiez-le (Ctrl+C)")

            # Deuxième ligne : Barre de progression + indicateur
            entropy = generator.calculate_entropy(st.session_state.password)
            strength = min(100, int(entropy * 0.8))
            
            # Utilisation de columns avec des ratios ajustés
            prog_col, text_col = st.columns([3, 1])
            with prog_col:
                st.progress(strength)
            with text_col:
                if strength > 80:
                    st.markdown(f"<div style='text-align: right; color: green;'>{strength}% - Excellent</div>", unsafe_allow_html=True)
                elif strength > 60:
                    st.markdown(f"<div style='text-align: right; color: orange;'>{strength}% - Bon</div>", unsafe_allow_html=True)
                else:
                    st.markdown(f"<div style='text-align: right; color: red;'>{strength}% - Faible</div>", unsafe_allow_html=True)


            col1, col2, col3 = st.columns(3)
            
            with col1:
                if st.button("📋 Copier", use_container_width=True):
                    st.session_state.copied = True
                    st.rerun()
            
            with col2:
                if st.button("🔍 Vérifier sécurité", use_container_width=True):
                    st.session_state.verify_pwd = st.session_state.password
                    st.session_state.selected_tab = "Vérification"
                    st.rerun()
            
            with col3:
                if st.button("⚡ Tester résistance", use_container_width=True):
                    st.session_state.attack_pwd = st.session_state.password
                    st.session_state.selected_tab = "Test de Résistance"
                    st.rerun()
            
            if "copied" in st.session_state:
                st.toast("Mot de passe copié!")
                del st.session_state.copied


elif st.session_state.get("selected_tab") == "ID + Mot de Passe":
    st.title("🔐 Générateur ID + Mot de Passe")
    
    with st.expander("Informations Utilisateur", expanded=True):
        full_name = st.text_input("Nom complet")
        email = st.text_input("Email")
    
    with st.expander("Configuration", expanded=True):
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Identifiant")
            id_length = st.slider("Longueur (4-32)", 4, 32, 8, key="id_length")
            id_use_upper = st.checkbox("Majuscules (A-Z)", value=False, key="id_upper")
            id_use_digits = st.checkbox("Chiffres (0-9)", value=True, key="id_digits")
            id_exclude_ambiguous = st.checkbox("Exclure caractères ambigus", value=False, key="id_ambiguous")
        
        with col2:
            st.subheader("Mot de Passe")
            id_pwd_length = st.slider("Longueur (8-64)", 8, 64, 12, key="pwd_length")
            id_pwd_upper = st.checkbox("Majuscules (A-Z)", value=True, key="pwd_upper")
            id_pwd_digits = st.checkbox("Chiffres (0-9)", value=True, key="pwd_digits")
            id_pwd_symbols = st.checkbox("Symboles (!@#)", value=True, key="pwd_symbols")
            id_pwd_ambiguous = st.checkbox("Exclure caractères ambigus", value=False, key="pwd_ambiguous")
    
    if st.button("🎲 Générer Identifiant + Mot de passe", use_container_width=True):
        if not full_name or not email:
            st.warning("Veuillez entrer votre nom complet et votre email.")
            st.stop()
        
        if not is_valid_email(email):
            st.error("L'adresse email saisie n'est pas valide. Veuillez corriger.")
            st.stop()
        
        identifier = generate_identifier(
            id_length,
            id_use_upper,
            id_use_digits,
            id_exclude_ambiguous
        )
        
        password = generator.generate_password(
            id_pwd_length,
            id_pwd_upper,
            id_pwd_digits,
            id_pwd_symbols,
            id_pwd_ambiguous
        )
        
        st.session_state.id_password = {
            "identifier": identifier,
            "password": password
        }
    
    if "id_password" in st.session_state:
        with st.container():
            col1, col2 = st.columns(2)

            with col1:
                st.markdown("**Identifiant généré**")
                st.code(st.session_state.id_password["identifier"], language="text")
                
                # Bouton de copie (méthode compatible cloud)
                if st.button("📋 Copier l'identifiant", key="copy_id"):
                    st.session_state.copied_id = st.session_state.id_password["identifier"]
                    st.code(st.session_state.copied_id, language="text")
                    st.toast("Sélectionnez l'identifiant ci-dessus et copiez-le (Ctrl+C)")
            
            with col2:
                show_pwd = st.checkbox("Afficher le mot de passe", key="id_pwd_checkbox")
                st.markdown("**Mot de passe généré**")
                st.text_input(
                    "Mot de passe",
                    value=st.session_state.id_password["password"],
                    type="default" if show_pwd else "password",
                    key="id_pwd_display",
                    label_visibility="collapsed"
                )

                if st.checkbox("Afficher version lisible", key="show_readable_id"):
                    readable_version = generator.create_readable_version(st.session_state.id_password["password"])
                    st.text_area(
                        "Version lisible",
                        value=readable_version,
                        key="readable_display_id",
                        height=69
                    )
                    
                    # Bouton de copie (méthode compatible cloud)
                    if st.button("📋 Copier version lisible", key="copy_readable_id"):
                        st.session_state.copied_readable = readable_version
                        st.code(st.session_state.copied_readable, language="text")
                        st.toast("Sélectionnez la version lisible ci-dessus et copiez-la (Ctrl+C)")

                # Bouton de copie du mot de passe (méthode compatible cloud)
                if st.button("📋 Copier le mot de passe", key="copy_pwd"):
                    st.session_state.copied_pwd = st.session_state.id_password["password"]
                    st.code(st.session_state.copied_pwd, language="text")
                    st.toast("Sélectionnez le mot de passe ci-dessus et copiez-le (Ctrl+C)")
        
        # Boutons d'actions en dessous
        st.divider()
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("🔍 Vérifier sécurité", key="verify_id_pwd", use_container_width=True):
                st.session_state.verify_pwd = st.session_state.id_password["password"]
                st.session_state.selected_tab = "Vérification"
                st.rerun()
        
        with col2:
            if st.button("⚡ Tester résistance", key="test_id_pwd", use_container_width=True):
                st.session_state.attack_pwd = st.session_state.id_password["password"]
                st.session_state.selected_tab = "Test de Résistance"
                st.rerun()
        

elif st.session_state.get("selected_tab") == "Vérification":
    st.title("🔍 Vérification de Mot de Passe")
    
    if 'verify_pwd' not in st.session_state:
        st.session_state.verify_pwd = ""
        
    show_verify_pwd = st.checkbox("Afficher le mot de passe", key="verify_pwd_checkbox")
    password = st.text_input(
        "Mot de passe à vérifier",
        value=st.session_state.verify_pwd,
        type="default" if show_verify_pwd else "password",
        key="verify_pwd_input",
    )

    if password != st.session_state.verify_pwd:
        st.session_state.verify_pwd = password
  
    if st.button("🔍 Vérifier", use_container_width=True):
        if not st.session_state.verify_pwd:
            st.warning("Veuillez entrer un mot de passe à vérifier")
            st.stop()
        
        with st.spinner("Analyse en cours..."):
            tab1, tab2, tab3 = st.tabs(["Résumé", "Analyse", "Recommandations"])
            
            # Analyse locale
            score, analysis = generator.evaluate_password_strength(password)
            
            # Vérification HIBP
            hibp_result = generator.check_hibp_status(password)
            
            # Générer les recommandations
            recommendations = []
            
            if hibp_result.get('compromised', False):
                recommendations.append((
                    f"CRITIQUE: Ce mot de passe a été compromis dans des fuites de données. "
                    f"Il a été trouvé {hibp_result['count']} fois. Vous devez le changer immédiatement.",
                    'danger'
                ))
            
            if analysis['length'] < 12:
                recommendations.append((
                    f"Le mot de passe est trop court ({analysis['length']} caractères). "
                    "Utilisez au moins 12 caractères.",
                    'danger' if analysis['length'] < 8 else 'warning'
                ))
            
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
            
            if not recommendations and entropy >= 70:
                recommendations.append((
                    "Excellent mot de passe! Conservez-le dans un gestionnaire de mots de passe sécurisé.",
                    'good'
                ))
            
            # Calcul du score
            score = 0
            
            if not hibp_result.get('compromised', False):
                length = analysis['length']
                if length >= 16: score += 30
                elif length >= 12: score += 20
                elif length >= 8: score += 10
                
                variety = 0
                if analysis['has_lower']: variety += 1
                if analysis['has_upper']: variety += 1
                if analysis['has_digit']: variety += 1
                if analysis['has_special']: variety += 1
                
                score += variety * 10
                
                if entropy >= 80: score += 30
                elif entropy >= 60: score += 20
                elif entropy >= 40: score += 10
                
                if analysis['common_patterns']: score -= 20
                if analysis['character_repetition']: score -= 15
                if analysis['keyboard_patterns']: score -= 10
            
            score = max(0, min(100, score))
            
            with tab1:
                st.subheader("Score de sécurité")

                st.metric("", f"{score}/100")
                
                if score >= 90:
                    st.success("Excellent - Sécurité maximale")
                elif score >= 75:
                    st.warning("Bon - Peut encore être amélioré")
                else:
                    st.error("Faible - Changez immédiatement")
                
                st.progress(score)
                
                st.subheader("Statut de compromission")
                
                if hibp_result.get('error'):
                    st.error(f"Erreur de vérification: {hibp_result['error']}")
                elif hibp_result.get('compromised', False):
                    st.error(f"COMPROMIS - Trouvé {hibp_result['count']} fois dans des fuites")
                else:
                    st.success("Non trouvé dans les bases compromises")
            
            with tab2:
                st.subheader("Analyse détaillée")
                
                data = [
                    ("Longueur", analysis['length'], generator.get_length_status(analysis['length'])),
                    ("Entropie", f"{analysis['entropy']:.1f} bits", generator.get_entropy_status(analysis['entropy'])),
                    ("Caractères uniques", analysis['unique_chars'], 
                    generator.get_variety_status(analysis['unique_chars'], analysis['length']))
                ]
                
                types = []
                if analysis['has_lower']: types.append("Minuscules")
                if analysis['has_upper']: types.append("Majuscules")
                if analysis['has_digit']: types.append("Chiffres")
                if analysis['has_special']: types.append("Symboles")
                
                data.append((
                    "Types de caractères", 
                    ', '.join(types) if types else "Aucun", 
                    generator.get_types_status(len(types))
                ))
                
                problems = []
                if analysis['common_patterns']: problems.append("Motifs courants")
                if analysis['character_repetition']: problems.append("Répétitions")
                if analysis['keyboard_patterns']: problems.append("Motifs clavier")
                            
                data.append((
                    "Problèmes détectés", 
                    ', '.join(problems) if problems else "Aucun", 
                    "danger" if problems else "good"
                ))
                
                for criteria, value, status in data:
                    if status == 'good':
                        st.success(f"{criteria}: {value}")
                    elif status == 'warning':
                        st.warning(f"{criteria}: {value}")
                    elif status == 'danger':
                        st.error(f"{criteria}: {value}")
                    else:
                        st.info(f"{criteria}: {value}")
            
            with tab3:
                st.subheader("Recommandations")
                
                if not recommendations:
                    st.success("Aucune recommandation - le mot de passe est sécurisé.")
            
                
                for text, level in recommendations:
                    if level == 'danger':
                        st.error(text)
                    elif level == 'warning':
                        st.warning(text)
                    elif level == 'good':
                        st.success(text)
                    else:
                        st.info(text)

elif st.session_state.get("selected_tab") == "Test de Résistance":
    st.title("⚡ Test de Résistance")
    
    if 'attack_pwd' not in st.session_state:
        st.session_state.attack_pwd = ""
    
    show_attack_pwd = st.checkbox("Afficher le mot de passe", key="attack_pwd_checkbox")
    password_input = st.text_input(
        "Mot de passe à tester",
        value=st.session_state.attack_pwd,
        type="default" if show_attack_pwd else "password",
        key="attack_pwd_input"
    )

    if password_input != st.session_state.attack_pwd:
        st.session_state.attack_pwd = password_input
    
    attack_types = [
        ("Force Brute Simple", "bruteforce"),
        ("Dictionnaire Classique", "dictionary"),
        ("Attaque par Motifs", "pattern_attack"),
        ("Attaque Rainbow Table", "rainbow"),
        ("Attaque Hybride", "hybrid_attack"),  
        ("Credential Stuffing", "credential_stuffing"),  
        ("Password Spraying", "password_spraying"),  
        ("Analyse d'Entropie", "entropy_analysis") 
    ]
    
    if 'selected_attacks' not in st.session_state:
        st.session_state.selected_attacks = [attack[1] for attack in attack_types]

    cols = st.columns(4)
    current_selected = []
    
    for i, (name, attack_id) in enumerate(attack_types):
        with cols[i % 4]:
            is_checked = st.checkbox(
                name,
                value=attack_id in st.session_state.selected_attacks,
                key=f"attack_{attack_id}_checkbox"
            )
            if is_checked:
                current_selected.append(attack_id)
    
    # Mise à jour des attaques sélectionnées
    st.session_state.selected_attacks = current_selected

    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("⚡ Lancer le Test", use_container_width=True):
            if not st.session_state.attack_pwd:
                st.warning("Veuillez entrer un mot de passe à tester")
                st.stop()
            
            if not st.session_state.selected_attacks:
                st.warning("Veuillez sélectionner au moins un type d'attaque")
                st.stop()
            
            with st.spinner("Simulation en cours..."):
                results = []
                for attack_type in st.session_state.selected_attacks:
                    try:
                        result = getattr(generator, f"simulate_{attack_type}")(st.session_state.attack_pwd)
                        results.append((attack_type, result))
                    except Exception as e:
                        results.append((attack_type, {"error": str(e)}))
                
                generator.display_attack_results(results, attack_types)

    with col2:
        if st.button("⚡ Tout Tester", use_container_width=True):
            if not st.session_state.attack_pwd:
                st.warning("Veuillez entrer un mot de passe à tester")
                st.stop()
            
            with st.spinner("Simulation complète en cours..."):
                results = []
                for name, attack_type in attack_types:
                    try:
                        result = getattr(generator, f"simulate_{attack_type}")(st.session_state.attack_pwd)
                        results.append((name, result))
                    except Exception as e:
                        results.append((name, {"error": str(e)}))
                
                generator.display_attack_results(results, attack_types, full_test=True)
    