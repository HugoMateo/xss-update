# XSS Watch

Journal de veille pour les techniques et vecteurs XSS utiles à un corpus de tests de sécurité autorisés.

## Règles de collecte

- Ne conserver que les nouveautés significatives et publiquement sourcées.
- Décrire les techniques de manière non destructive ; pas d'exfiltration, de vol de session ni de contournement offensif automatisé.
- Privilégier les cas reproductibles comme tests de régression : contexte, pipeline de parsing/sanitisation, moteur navigateur, version affectée et correctif.
- Dédupliquer par CVE/GHSA ou, à défaut, par famille technique + source primaire.
- Statuts : `nouveau`, `à intégrer`, `intégré`, `archivé`.

## Schéma d'une entrée

```yaml
date_publication: YYYY-MM-DD
date_veille: YYYY-MM-DD
famille: mxss | dom-xss | stored-xss | svg | sanitizer | parser-differential | autre
contexte: description courte
produit: nom/version si applicable
navigateurs: []
identifiants: []
statut: nouveau
source: URL
```

---

## 2026-08

### 2026-08-28 — Pocket Android <= 8.33.0.0 — HTML externe injecté dans une WebView avec pont natif

- **Famille :** `webview-xss`, `dom-xss`, `native-bridge`, `mobile`
- **Contexte :** la fonction « Save to Pocket » charge du HTML externe dans le DOM d'une WebView ; du JavaScript exécuté dans ce contexte peut atteindre des méthodes de pont natif et modifier l'état de l'application.
- **Produit :** Pocket Android <= 8.33.0.0.
- **Navigateurs :** Android WebView / moteur Chromium embarqué.
- **Identifiants :** CVE-2026-82090.
- **Plateforme / source d'origine :** publication CVE/MITRE du 28 août 2026, avec description technique publique référencée sur GitHub.
- **Description non destructive :** tester uniquement qu'un fragment HTML externe comportant un marqueur neutre est interprété comme contenu actif dans la WebView et qu'une interface JavaScript exposée est visible depuis ce contexte, sans invoquer de méthode modifiant des données ou l'état applicatif.
- **Intérêt corpus :** ajouter une classe `external HTML -> WebView DOM -> JS bridge exposure` distincte des XSS navigateur classiques. Vérifier séparément la sanitisation du HTML, l'origine du contenu, l'activation de JavaScript et l'exposition des interfaces natives.
- **Statut :** `à intégrer`
- **Sources :** https://www.cve.org/CVERecord?id=CVE-2026-82090 ; https://vulnerability.circl.lu/vuln/cve-2026-82090 ; https://github.com/FUNFACTOR1/pocket-android-xss-0click-cve

### 2026-08-28 — wallabag Android <= 2.6.0 — données API rendues directement dans une WebView

- **Famille :** `webview-xss`, `stored-xss`, `api-to-dom`, `mobile`
- **Contexte :** des données d'entrées récupérées via `/api/entries` sont chargées dans une WebView Android sans frontière de confiance suffisante entre contenu serveur et contexte de rendu actif.
- **Produit :** wallabag Android <= 2.6.0.
- **Navigateurs :** Android WebView.
- **Identifiants :** CVE-2026-82089 / GHSA-q2g2-www6-wf5h.
- **Plateforme / source d'origine :** CVE/MITRE et advisory GitHub wallabag, publiés/référencés le 28 août 2026.
- **Description non destructive :** injecter dans une entrée de test autorisée un marqueur HTML inoffensif et vérifier si la chaîne `API -> stockage/cache -> WebView` le transforme en DOM actif. Ne pas utiliser d'appel réseau, de lecture de secrets ni d'API natives.
- **Intérêt corpus :** couvrir les XSS dont la source est une API applicative considérée à tort comme « de confiance », notamment dans les clients mobiles hybrides. Ajouter des variantes avec contenu persistant, synchronisation et lecture hors-ligne.
- **Statut :** `à intégrer`
- **Sources :** https://www.cve.org/CVERecord?id=CVE-2026-82089 ; https://vulnerability.circl.lu/vuln/cve-2026-82089 ; https://github.com/wallabag/wallabag/security/advisories/GHSA-q2g2-www6-wf5h

### 2026-08-27 — Netron <= 9.1.2 — DOM XSS dans une application desktop Electron via champs de modèle

- **Famille :** `dom-xss`, `electron`, `desktop`, `innerhtml`
- **Contexte :** des champs contrôlés par un fichier de modèle sont rendus dans la barre latérale via HTML non échappé ; dans l'application desktop Electron, le script s'exécute dans un contexte plus privilégié qu'une page web ordinaire.
- **Produit :** Netron <= 9.1.2 ; corrigé à partir de 9.1.3.
- **Navigateurs :** Electron 42.3.3 / Chromium embarqué selon l'advisory.
- **Identifiants :** CVE-2026-79718, CVE-2026-79719, CVE-2026-79720.
- **Plateforme / source d'origine :** HiddenLayer SAI Security Advisory, Esteban Tonglet, publié le 27 août 2026.
- **Description non destructive :** ouvrir uniquement un modèle de test local contenant un marqueur HTML neutre dans un champ de nom et vérifier s'il devient un nœud DOM interprété dans la barre latérale. Ne pas effectuer de requêtes réseau ni tester de chaîne vers une vulnérabilité du moteur Chromium.
- **Intérêt corpus :** ajouter une classe `untrusted file metadata -> innerHTML -> Electron renderer`, avec comparaison entre rendu web et application desktop. Ce cas rappelle qu'une XSS dans un shell Electron doit être testée avec des contraintes de contexte distinctes d'une XSS navigateur.
- **Statut :** `à intégrer`
- **Sources :** https://www.hiddenlayer.com/sai-security-advisory/2026-08-netron ; https://github.com/lutzroeder/netron/commit/cd14bad8c9132b1aaf1d197fe61925575f194f00

### 2026-08-26 — SunEditor <= 3.1.3 — DOM XSS dans le plugin Embed après parsing d'iframe

- **Famille :** `dom-xss`, `sanitizer-bypass`, `domparser`, `editor-embed`
- **Contexte :** contenu HTML fourni au plugin Embed, parsé avec `DOMParser`, puis certains nœuds sont recréés et ajoutés au DOM actif après un embed valide.
- **Produit :** SunEditor <= 3.1.3 ; corrigé en 3.1.4.
- **Navigateurs :** navigateurs exécutant le DOM standard ; le problème est lié au flux applicatif du plugin plutôt qu'à une divergence moteur spécifique.
- **Identifiants :** CVE-2026-54606 / GHSA-w93q-cq9w-58p7.
- **Plateforme / source d'origine :** advisory SunEditor / GitHub Security Advisory ; CVE publié/indexé le 26 août 2026.
- **Description non destructive :** le plugin analyse un fragment d'embed, puis peut recréer un élément externe contrôlé par l'entrée et l'attacher au document actif. Pour un corpus autorisé, remplacer toute ressource active par un marqueur local neutre et vérifier uniquement qu'un nœud inattendu survit au pipeline `parse -> inspect -> recreate -> append`.
- **Intérêt corpus :** ajouter des tests où un élément autorisé sert de préfixe à des nœuds frères non attendus ; vérifier que la sanitisation porte sur l'ensemble du fragment et qu'aucun nœud actif n'est recréé après validation. Ce cas complète les tests classiques de sanitisation en ciblant la réintroduction d'un nœud après `DOMParser`.
- **Statut :** `à intégrer`
- **Sources :** https://github.com/JiHong88/suneditor/security/advisories/GHSA-w93q-cq9w-58p7 ; https://nvd.nist.gov/vuln/detail/CVE-2026-54606 ; https://advisories.gitlab.com/npm/suneditor/CVE-2026-54606/

### 2026-08-25 — PortSwigger — nom de balise comme source JavaScript / transformation DOM

- **Famille :** `dom-xss`, `parser-differential`, `waf-bypass`, `html-parser`
- **Contexte :** balises HTML non standard dont le nom est relu via des propriétés DOM telles que `localName`, puis réutilisé comme donnée dans un contexte JavaScript, URL ou HTML.
- **Produit :** comportement navigateur / DOM, pas un produit unique.
- **Navigateurs :** Chrome/Blink, Firefox/Gecko, Safari/WebKit et Edge selon la publication.
- **Identifiants :** aucun CVE ; recherche PortSwigger.
- **Plateforme / source d'origine :** PortSwigger Research, Gareth Heyes.
- **Description non destructive :** la recherche montre que le nom d'une balise peut transporter une chaîne transformée par le parseur puis être relue par le DOM avec une casse ou une segmentation différente. Des propriétés comme `localName`, `part` et `classList` peuvent ensuite fournir ces données à un gestionnaire d'événement ou à une API DOM. Pour le corpus, utiliser uniquement des marqueurs inoffensifs et vérifier la transformation `source HTML -> DOM -> valeur relue`, sans exécution sensible.
- **Intérêt corpus :** ajouter des cas où la charge utile logique n'est pas portée par un attribut classique mais par le **tag name** lui-même ; couvrir les transformations de casse, caractères inhabituels, séparateurs Unicode, focusabilité (`tabindex`/`contenteditable`) et réutilisation via `localName`, `part` ou `classList`. Ces cas sont particulièrement utiles pour évaluer les blocklists, normalisations et signatures WAF qui supposent des noms de balises conventionnels.
- **Statut :** `à intégrer`
- **Source :** https://portswigger.net/research/whats-in-a-tag-name-javascript-apparently

### 2026-08-23 — justhtml <= 1.13.0 — parser differential / mutation XSS

- **Famille :** `mxss`, `parser-differential`, `sanitizer`
- **Contexte :** politique de sanitisation personnalisée conservant des namespaces étrangers tels que SVG/MathML ou certains conteneurs raw-text.
- **Produit :** justhtml <= 1.13.0 ; corrigé en 1.14.0.
- **Identifiant :** CVE-2026-5751 / GHSA-r758-8hxw-4845.
- **Description non destructive :** une entrée peut être considérée sûre après sanitisation mais produire un DOM différent et potentiellement actif après re-parsing. Le cas de test recommandé compare le DOM sérialisé avant/après re-parsing avec un marqueur inoffensif.
- **Intérêt corpus :** ajouter un pipeline `sanitize -> serialize -> reparse -> compare DOM`, avec dimensions SVG, MathML, raw-text et custom policy.
- **Statut :** `à intégrer`
- **Sources :** https://nvd.nist.gov/vuln/detail/CVE-2026-5751 ; https://github.com/EmilStenstrom/justhtml/security/advisories/GHSA-r758-8hxw-4845

### 2026-08-23 — justhtml <= 1.11.0 — HTML vers Markdown puis rendu HTML

- **Famille :** `sanitizer`, `representation-change`
- **Contexte :** conversion d'un document parsé vers Markdown via `to_markdown()`, suivie d'un rendu Markdown acceptant le HTML brut.
- **Produit :** justhtml <= 1.11.0 ; corrigé en 1.12.0.
- **Identifiant :** CVE-2026-8445 / GHSA-3rcm-vjrc-p45j.
- **Description non destructive :** certains caractères HTML significatifs présents dans des nœuds texte peuvent être réémis tels quels dans le Markdown et retrouver une sémantique HTML lors d'un rendu ultérieur. Les tests doivent utiliser des marqueurs inoffensifs et vérifier le changement de représentation.
- **Intérêt corpus :** ajouter un pipeline `HTML -> parser/sanitizer -> Markdown -> Markdown renderer -> HTML` et vérifier les différences d'interprétation.
- **Statut :** `à intégrer`
- **Sources :** https://nvd.nist.gov/vuln/detail/CVE-2026-8445 ; https://github.com/EmilStenstrom/justhtml/security/advisories/GHSA-3rcm-vjrc-p45j

### 2026-08-17 — DOMPurify <= 3.2.6 — SVG SMIL `animateTransform` spécifique Safari

- **Famille :** `svg`, `sanitizer`, `browser-differential`
- **Contexte :** traitement d'attributs animés SVG/SMIL et différence d'implémentation entre WebKit, Blink et Gecko.
- **Produit :** anciennes branches DOMPurify <= 3.2.6 pour ce vecteur ; les versions récentes comportent des contrôles supplémentaires sur les `href` animés.
- **Navigateurs :** Safari/WebKit principalement.
- **Description non destructive :** la recherche montre qu'une divergence du moteur SVG peut modifier la valeur animée d'un attribut après sanitisation. Pour le corpus, tester la structure et l'évolution des attributs avec un marqueur neutre plutôt qu'une action JavaScript sensible.
- **Limites publiées :** interaction utilisateur requise et dépendance aux règles CSP autorisant certains schémas d'URL.
- **Intérêt corpus :** introduire l'axe `engine = Blink | Gecko | WebKit` dans les tests SVG et comparer `baseVal`/`animVal` lorsqu'applicable.
- **Statut :** `à intégrer`
- **Source :** https://mizu.re/post/dompurify-bypass-smil-animatetransform-safari

### 2026-08-03 — DOMPurify <= 3.4.12 — subtree détaché avec `IN_PLACE`

- **Famille :** `sanitizer`, `dom-xss`, `lifecycle`
- **Contexte :** sanitisation `IN_PLACE` avec hook retirant un élément pendant le parcours.
- **Produit :** DOMPurify <= 3.4.12 ; corrigé en 3.4.13.
- **Identifiant :** GHSA-55q2-fjhq-7xh7.
- **Description non destructive :** lorsqu'un hook détache un nœud, certains descendants pouvaient rester actifs alors même que la racine retournée paraissait propre. Un test de régression peut vérifier qu'aucun descendant détaché ne conserve de gestionnaire actif, avec un simple marqueur local.
- **Intérêt corpus :** ajouter des scénarios de cycle de vie DOM : `dirty subtree -> hook removal -> detached descendants -> post-sanitize state`.
- **Statut :** `à intégrer`
- **Source :** https://github.com/cure53/DOMPurify/security/advisories/GHSA-55q2-fjhq-7xh7

---

## Journal de mise à jour

- **2026-08-28** — Ajout de trois familles significatives : Pocket Android (HTML externe vers WebView avec pont natif), wallabag Android (API vers WebView) et Netron desktop (métadonnées de fichier vers `innerHTML` dans Electron).
- **2026-08-27** — Ajout de CVE-2026-54606 / GHSA-w93q-cq9w-58p7 : réintroduction d'un nœud actif après parsing d'un fragment Embed dans SunEditor.
- **2026-08-26** — Ajout de la recherche PortSwigger du 25 août sur l'utilisation du nom de balise comme source JavaScript / transformation DOM.
- **2026-08-25** — Initialisation du fichier et ajout des premières entrées vérifiées de la veille d'août 2026.
