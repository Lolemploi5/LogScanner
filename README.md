# LogScanner

Log Scanner est un outil de scan de fichiers de log avec des options de configuration flexibles et des suggestions de solutions. Vous pouvez utiliser cet outil via le terminal avec `LogScanner.py` ou via une interface utilisateur graphique avec `LogScannerUI.py`.

## Installation

### Prérequis

- Python 3.x
- Pip (gestionnaire de paquets Python)

### Étapes d'installation

1. Clonez ce dépôt ou téléchargez les fichiers nécessaires.

```
git clone https://github.com/Lolemploi5/LogScanner.git
cd log-scanner
```
Installez les dépendances requises à partir du fichier requirements.txt.
```
pip install -r requirements.txt
```
**Fichiers de configuration :**
* `config/config.json` : Fichier de configuration contenant les motifs (patterns) de recherche.
* `config/error_solutions.json` : Fichier contenant les solutions pour les erreurs détectées.
Assurez-vous que ces fichiers sont présents et correctement configurés avant d'utiliser les scripts.

### Utilisation
Utilisation via le `terminal`
Assurez-vous que les fichiers de configuration sont présents dans le dossier config.
Placez les fichiers de log à analyser dans un dossier spécifique (par exemple, logscan).
Exécutez le script `LogScanner.py` :
```
python LogScanner.py
```
Suivez les instructions à l'écran pour sélectionner le fichier de log à scanner et obtenir le rapport d'analyse.
Utilisation via l'interface utilisateur (UI)
Assurez-vous que les fichiers de configuration sont présents dans le dossier config.
Exécutez le script `LogScannerUI.py` :
```
python LogScannerUI.py
```
Utilisez l'interface utilisateur pour :
* Sélectionner le fichier de configuration.
* Sélectionner le fichier de solutions.
* Parcourir et sélectionner les fichiers de log à analyser.
* Lancer le scan et afficher les rapports et suggestions.
### Fonctionnalités
`LogScanner.py` :

* Analyse des fichiers de log via le terminal.
* Génération de rapports avec les niveaux de sévérité et suggestions de solutions.
* Affichage des statistiques et visualisation graphique des résultats.
`LogScannerUI.py` :

* Interface utilisateur graphique pour une utilisation plus conviviale.
* Sélection facile des fichiers de configuration et de log.
* Affichage des résultats d'analyse et des suggestions directement dans l'UI.
* Visualisation des statistiques sous forme de graphique.
### Exemple de configuration (`config/config.json`)
```
{
    "patterns": {
        "ERROR": "error",
        "WARNING": "warning",
        "INFO": "info",
        "DEBUG": "debug"
    }
}
```
### Exemple de solutions (`config/error_solutions.json`)
```
{
    "ERROR": {
        "ConnectionError": "Check your internet connection.",
        "FileNotFoundError": "Ensure the file exists and the path is correct."
    },
    "WARNING": {
        "DeprecationWarning": "Update your code to use supported methods."
    }
}
```
### Contributions
Les contributions sont les bienvenues ! Veuillez soumettre une pull request ou ouvrir une issue pour discuter des changements que vous souhaitez apporter.

Ce `README.md` explique clairement comment installer et utiliser les deux versions de votre outil, avec des exemples de configuration pour aider les utilisateurs à démarrer rapidement.