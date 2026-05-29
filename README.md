# izinscope

**izinscope** est un outil en ligne de commande permettant de vérifier si des adresses IP ou des domaines se trouvent dans un “scope” défini (IP, CIDR, domaines résolus). Il facilite l’identification des ressources *in-scope* et peut générer des rapports en format TXT ou CSV.

---

## Installation

### Via pipx (recommandé)

Assurez-vous d’avoir [pipx](https://pypa.github.io/pipx/) installé, puis exécutez :

```bash
pipx install git+https://github.com/MahafalyRandriamiarisoa/izinscope.git
```

Vous pouvez alors utiliser la commande `izinscope` depuis votre terminal.

### Installation locale avec Poetry

1. **Cloner** le dépôt :

   ```bash
   git clone https://github.com/MahafalyRandriamiarisoa/izinscope.git
   cd izinscope
   ```

2. **Installer** les dépendances :

   ```bash
   poetry install
   ```

3. **Lancer** la commande en local :

   ```bash
   poetry run izinscope --help
   ```

---

## Utilisation

### Vérifier une IP unique

```bash
izinscope -s scope.txt -i 192.168.10.5
```

- `-s, --scope` : Fichier **ou dossier** contenant ton “scope” (CIDR, IP, domaines). Répétable ; un dossier est parcouru récursivement (les fichiers cachés sont ignorés).
- `-i, --single-check` : Vérification d’une seule IP ou d’un seul domaine.

### Vérifier un fichier de domaines

```bash
izinscope -s scope.txt -d domains.txt --debug -oT out.txt -oC out.csv
```

- `-d, --domains-to-check` : Fichier listant les domaines à vérifier.
- `--debug` : Active un mode de logs détaillés (fichier log).
- `-oT, --output-txt` : Nom du fichier de sortie TXT (un domaine par ligne).
- `-oC, --output-csv` : Nom du fichier de sortie CSV (colonnes : `domain,ip,entry,file`).

### Options supplémentaires

- `-od, --only-domain` : N’affiche que les domaines/cibles in-scope sur la sortie standard.
- `--timeout` : Timeout DNS en secondes (défaut : `3`).
- `-V, --version` : Affiche la version d’**izinscope**.
- `--help` : Affiche l’aide.

---

## Exemple de fichier scope

```
# Les lignes commençant par # sont des commentaires
192.168.0.0/24
10.0.0.1        # un commentaire en fin de ligne est aussi ignoré
example.com
```

- **CIDR** : `192.168.0.0/24`
- **IP unique** : `10.0.0.1`
- **Domaine** : `example.com` (résolution DNS en IPv4/IPv6)
- **Commentaires** : tout ce qui suit `#` est ignoré (ligne entière ou fin de ligne)

---

## Points clés

- **Résolution DNS** : géré via `dnspython`, pour couvrir IPv4 et IPv6 (y compris pour les domaines présents dans le scope).
- **Scope multi-sources** : plusieurs `-s` cumulables, fichiers comme dossiers (parcours récursif).
- **Multithreading** : le script peut résoudre plusieurs domaines en parallèle, accélérant l’analyse de grandes listes.
- **Logs** : en mode `--debug`, un fichier de log horodaté (sans codes couleur) est généré pour chaque exécution.
- **Rapports** : génération d’un fichier CSV (`domain,ip,entry,file`) et d’un fichier TXT (un domaine in-scope par ligne).

---

## Licence

Distribué sous licence **MIT**. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

---

## Contributions

Les contributions sont les bienvenues sous forme de _pull requests_. Merci d’ouvrir une _issue_ pour discuter des améliorations ou signaler des bugs avant de proposer un PR.

---

Bon usage ! 
