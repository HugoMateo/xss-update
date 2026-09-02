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

## 2026-09

### 2026-09-01 — league/commonmark < 2.9.1 — filtre `on*` contourné par U+000C FORM FEED

- **Famille :** `stored-xss`, `parser-differential`, `control-character`, `markdown-to-html`, `sanitizer-bypass`
- **Contexte :** dans `AttributesExtension`, un caractère U+000C FORM FEED placé avant un nom d'attribut empêche les comparaisons de sécurité de reconnaître correctement les attributs commençant par `on` et peut également perturber le contrôle des liens non sûrs. Le caractère reste présent lors du filtrage côté PHP mais est ensuite traité comme un séparateur/whitespace pertinent par le parseur HTML du navigateur.
- **Produit :** league/commonmark >= 2.7.0 et < 2.9.1 ; corrigé en 2.9.1.
- **Navigateurs :** navigateurs HTML standards ; l'intérêt vient de la différence de normalisation entre le filtre applicatif et le parseur HTML.
- **Identifiants :** GHSA-f8fg-pg57-v4j8.
- **Plateforme / source d'origine :** GitHub Security Advisory thephpleague/commonmark, recoupé avec OSV et la release 2.9.1.
- **Description non destructive :** dans un convertisseur Markdown de test utilisant `AttributesExtension`, préfixer uniquement un attribut sentinelle inoffensif par U+000C et comparer la chaîne HTML produite avec le DOM réellement construit par le navigateur. Le test doit signaler toute différence de nom/normalisation d'attribut sans exécuter de JavaScript ni utiliser de schéma d'URL actif.
- **Intérêt corpus :** ajouter une famille `filter normalization -> serializer -> browser parser normalization` couvrant les caractères de contrôle ASCII, en particulier U+000C. Vérifier séparément les noms d'attributs et les valeurs d'URL, car la même divergence peut affecter plusieurs garde-fous. Ce cas est particulièrement utile pour tester les correctifs de blocklist/allowlist après sérialisation et les écarts entre fonctions de trimming côté serveur et définition HTML des espaces.
- **Statut :** `à intégrer`
- **Sources :** https://github.com/thephpleague/commonmark/security/advisories/GHSA-f8fg-pg57-v4j8 ; https://osv.dev/vulnerability/GHSA-f8fg-pg57-v4j8 ; https://github.com/thephpleague/commonmark/releases/tag/2.9.1

### 2026-09-01 — WPBakery Page Builder <= 8.7.4 — sanitisation avant décodage Base64 puis rendu brut

- **Famille :** `stored-xss`, `representation-change`, `decode-after-sanitize`, `wordpress`, `shortcode`
- **Contexte :** le paramètre `data` du shortcode de HTML brut est sauvegardé sous forme Base64. La sanitisation `wp_kses_post()` intervient alors que le contenu actif est encore représenté comme texte alphanumérique, puis le template `vc_raw_html` décode la valeur au moment du rendu et l'émet sans échappement contextuel suffisant.
- **Produit :** WPBakery Page Builder <= 8.7.4.
- **Navigateurs :** navigateurs web standards ; la faiblesse est dans l'ordre des transformations côté application.
- **Identifiants :** CVE-2026-15101.
- **Plateforme / source d'origine :** Wordfence CNA / WordPress plugin source, recoupé avec l'enregistrement CVE publié le 1er septembre 2026.
- **Description non destructive :** dans une installation de test, encoder en Base64 uniquement un fragment HTML sentinelle inoffensif, le faire passer par le chemin de sauvegarde concerné, puis vérifier après décodage si le fragment est réinterprété comme DOM plutôt que comme texte. Ne pas inclure de gestionnaire d'événement, d'URL active ou de JavaScript.
- **Intérêt corpus :** ajouter un pipeline `encode -> sanitize encoded representation -> persist -> decode -> raw render` et sa variante inverse `decode -> sanitize -> render`. Ce cas permet de détecter les protections appliquées à une représentation qui n'est pas celle finalement interprétée par le navigateur et généralise au-delà de Base64 vers URL encoding, entités, compression ou autres transformations tardives.
- **Statut :** `à intégrer`
- **Sources :** https://www.wordfence.com/threat-intel/vulnerabilities/id/b61ced52-30a2-407a-8659-1ae4a4d99aab ; https://www.cve.org/CVERecord?id=CVE-2026-15101 ; https://plugins.trac.wordpress.org/browser/js_composer/trunk/include/templates/shortcodes/vc_raw_html.php#L30

## 2026-08

### 2026-08-31 — Helix Ultimate < 2.2.10 — configuration MegaMenu JSON persistée puis rendue dans plusieurs contextes

- **Famille :** `stored-xss`, `json-to-html`, `contextual-escaping`, `cms`, `multi-sink`
- **Contexte :** des valeurs de configuration de colonnes et d'éléments du MegaMenu sont persistées dans le JSON de layout puis réutilisées dans le rendu. Les versions antérieures à 2.2.10 n'appliquaient pas un filtrage et un échappement contextuel complets sur ces valeurs ; la release 2.2.10 durcit également plusieurs surfaces voisines, notamment les embeds vidéo/audio, les handlers de partage social et certains attributs de titre.
- **Produit :** JoomShaper Helix Ultimate < 2.2.10 ; version 2.2.10 publiée le 27 août 2026 avec les correctifs, CVE/GHSA publiés le 31 août 2026.
- **Navigateurs :** navigateurs web standards ; aucune divergence moteur spécifique n'est nécessaire.
- **Identifiants :** CVE-2026-78077 / GHSA-v6p2-jx9w-8967.
- **Plateforme / source d'origine :** Joomla CNA / GitHub Advisory Database, recoupé avec les notes de version officielles JoomShaper 2.2.10.
- **Description non destructive :** dans une instance Joomla de test autorisée, enregistrer dans les champs de configuration MegaMenu uniquement des marqueurs HTML neutres et vérifier, pour chaque surface de rendu, si la valeur reste du texte ou devient un nœud DOM. Ne pas exécuter de JavaScript, ne pas utiliser de données de session et ne pas combiner avec les faiblesses d'autorisation publiées séparément.
- **Intérêt corpus :** ajouter une matrice `persistent JSON config -> renderer/context`, en couvrant texte, attribut, URL/identifiant d'embed et handlers générés. Le cas est utile pour détecter les corrections partielles où une validation à l'entrée paraît suffisante mais où une même valeur est réinterprétée dans plusieurs contextes nécessitant des encodeurs différents. Ajouter également un contrôle de régression sur le couple `InputFilter -> contextual output encoding` plutôt qu'une simple blocklist de chaînes.
- **Statut :** `à intégrer`
- **Sources :** https://github.com/advisories/GHSA-v6p2-jx9w-8967 ; https://www.cve.org/CVERecord?id=CVE-2026-78077 ; https://www.joomshaper.com/downloads/template/helixultimate/

### 2026-08-30 — Readest < 0.11.16 — `iframe srcdoc` survivant à la sanitisation EPUB dans un shell Tauri

- **Famille :** `dom-xss`, `sanitizer-bypass`, `srcdoc`, `desktop`, `tauri`
- **Contexte :** le contenu HTML des chapitres EPUB passe par DOMPurify, mais la configuration concernée interdisait principalement `script` sans bloquer `iframe`/`object`/`embed` ni l'attribut `srcdoc`. Un document imbriqué pouvait donc conserver une interprétation HTML active après sanitisation.
- **Produit :** Readest < 0.11.16 ; corrigé en 0.11.16.
- **Navigateurs :** moteur WebView embarqué par l'application desktop Tauri sous Windows, macOS et Linux ; le point important est la frontière entre contenu EPUB non fiable et contexte applicatif.
- **Identifiants :** CVE-2026-82642 / GHSA-p4x7-pf2c-xrvj.
- **Plateforme / source d'origine :** JFrog Security Research / GitHub Security Advisory Readest, avec correctif et release publics.
- **Description non destructive :** dans une copie de test locale d'un EPUB, placer uniquement un marqueur visuel neutre dans un document `srcdoc` et vérifier s'il apparaît après le pipeline de sanitisation et rendu. Ne pas invoquer d'IPC Tauri, de commande système, d'accès fichier ou de lecture de secrets.
- **Intérêt corpus :** ajouter un pipeline `untrusted EPUB HTML -> DOMPurify config -> iframe/srcdoc nested document -> desktop WebView`, en vérifiant séparément les listes `FORBID_TAGS` et `FORBID_ATTR`. Ce cas est particulièrement utile pour détecter les sanitizers qui raisonnent sur le DOM parent mais laissent un second document HTML opaque dans un attribut.
- **Statut :** `à intégrer`
- **Sources :** https://github.com/readest/readest/security/advisories/GHSA-p4x7-pf2c-xrvj ; https://github.com/readest/readest/pull/4762 ; https://github.com/readest/readest/commit/005aa2d6157a34049bf45641c06861d606a85edb ; https://github.com/readest/readest/releases/tag/v0.11.16 ; https://www.cve.org/CVERecord?id=CVE-2026-82642

### 2026-08-30 — SiYuan < 3.8.1 — métadonnées de blocs non échappées dans hints, backlinks et breadcrumbs

- **Famille :** `stored-xss`, `metadata-to-dom`, `multi-sink`, `knowledge-base`
- **Contexte :** des champs persistants de bloc tels que nom, alias et mémo sont réutilisés dans plusieurs surfaces de rendu — hints, backlinks et breadcrumbs — sans échappement suffisant.
- **Produit :** SiYuan < 3.8.1 ; 3.8.1 indiqué comme non affecté dans les données CVE publiées.
- **Navigateurs :** contexte de rendu web/desktop de SiYuan ; aucune divergence moteur particulière n'est nécessaire d'après les advisories publics.
- **Identifiants :** CVE-2026-82654 / GHSA-hf87-qh3j-3p88.
- **Plateforme / source d'origine :** GitHub Security Advisory SiYuan, recoupé avec l'enregistrement CVE/VulnCheck publié le 30 août 2026.
- **Description non destructive :** créer dans un espace de test un bloc dont le nom, l'alias ou le mémo contient seulement un marqueur HTML neutre, puis ouvrir les vues qui réutilisent cette métadonnée et relever où le marqueur devient un nœud DOM plutôt qu'un texte échappé. Ne pas exécuter de JavaScript ni accéder aux données d'autres utilisateurs.
- **Intérêt corpus :** ajouter une famille `persistent metadata -> multiple secondary renderers`, avec matrice `field × sink` couvrant nom/alias/mémo et hint/backlink/breadcrumb. Cette famille permet de détecter les corrections partielles où le rendu principal est sécurisé mais une vue secondaire conserve un sink HTML.
- **Statut :** `à intégrer`
- **Sources :** https://github.com/siyuan-note/siyuan/security/advisories/GHSA-hf87-qh3j-3p88 ; https://www.vulncheck.com/advisories/siyuan-before-3.8.1-stored-xss-via-block-name ; https://www.cve.org/CVERecord?id=CVE-2026-82654

### 2026-08-29 — Formwork — source `Referer` persistée puis rendue dans les statistiques admin

- **Famille :** `stored-xss`, `http-header`, `analytics`, `admin-ui`, `trust-boundary`
- **Contexte :** le suivi des visites extrait l'hôte de l'en-tête HTTP `Referer`, le stocke comme source de trafic puis l'affiche dans le panneau Statistics sans neutralisation suffisante.
- **Produit :** Formwork. Le GHSA primaire indique 2.0.0–2.3.10 affectées et 2.3.11 corrigée ; le CVE-2026-82451 publié le 29 août indique pour sa part des versions affectées jusqu'à 2.3.14. Cette divergence de métadonnées doit être conservée dans le corpus plutôt que résolue par supposition.
- **Navigateurs :** navigateurs web standards ; aucun moteur particulier n'est requis par l'advisory.
- **Identifiants :** CVE-2026-82451 / GHSA-hpgc-57cm-66pc.
- **Plateforme / source d'origine :** GitHub Security Advisory getformwork/formwork, complété par le CVE publié le 29 août 2026.
- **Description non destructive :** dans une instance de test autorisée, enregistrer une valeur de `Referer` contenant uniquement un marqueur HTML neutre, puis vérifier si la valeur est persistée et réinterprétée comme balisage lors de l'ouverture du panneau Statistics. Ne pas utiliser de JavaScript actif, de collecte de session ni d'action privilégiée.
- **Intérêt corpus :** ajouter une chaîne `HTTP metadata -> analytics persistence -> privileged HTML sink`. Ce cas est utile pour vérifier que les journaux, statistiques et données de télémétrie ne sont jamais considérés comme fiables simplement parce qu'ils proviennent de métadonnées HTTP.
- **Statut :** `à intégrer`
- **Sources :** https://github.com/getformwork/formwork/security/advisories/GHSA-hpgc-57cm-66pc ; https://www.cve.org/CVERecord?id=CVE-2026-82451 ; https://vulnerability.circl.lu/vuln/cve-2026-82451

### 2026-08-28 — PrivateBin <= 2.0.4 — type MIME contrôlé et `blob:` same-origin dans le lien de téléchargement

- **Famille :** `stored-xss`, `blob-url`, `mime-confusion`, `sanitizer-gap`, `csp-dependent`
- **Contexte :** une pièce jointe déchiffrée côté client fournit un type MIME contrôlé par l'entrée. Le lien de téléchargement peut pointer vers un `blob:` non assaini tandis que la branche de sanitisation ne traite que certains aperçus SVG.
- **Produit :** PrivateBin <= 2.0.4 ; corrigé en 2.0.5.
- **Navigateurs :** comportement confirmé avec Chromium dans l'advisory ; le risque repose plus généralement sur le rendu d'un `blob:` actif dans l'origine de l'application.
- **Identifiants :** CVE-2026-55696 / GHSA-f2xf-7x3g-4272.
- **Plateforme / source d'origine :** advisory GitHub PrivateBin ; publication dans la GitHub Advisory Database et CVE le 28 août 2026.
- **Description non destructive :** sur une instance de test avec upload activé, générer une pièce jointe inoffensive déclarée avec plusieurs types MIME et vérifier si l'action « ouvrir dans un nouvel onglet » produit un document `blob:` rendu dans l'origine applicative. Utiliser uniquement un marqueur visuel local et ne lire ni cookies, ni stockage local, ni ressources same-origin.
- **Intérêt corpus :** ajouter une chaîne `attacker-controlled MIME -> Blob(Content-Type) -> download href -> new-tab navigation -> origin inheritance`, en distinguant le blob utilisé pour l'aperçu de celui utilisé pour le téléchargement. Tester également l'effet d'une CSP recommandée, affaiblie ou absente.
- **Statut :** `à intégrer`
- **Sources :** https://github.com/PrivateBin/PrivateBin/security/advisories/GHSA-f2xf-7x3g-4272 ; https://github.com/PrivateBin/PrivateBin/releases/tag/2.0.5 ; https://www.cve.org/CVERecord?id=CVE-2026-55696

### 2026-08-27 — LiteSpeed Cache <= 7.7 — transformation regex d'attributs `<img>` créant une XSS stockée

- **Famille :** `stored-xss`, `html-rewrite`, `regex-parser`, `attribute-boundary`, `wordpress`
- **Contexte :** lorsque « Lazy Load Images » et « Add Missing Sizes » sont activés, une expression régulière utilisée pour retirer/réécrire les attributs `width` et `height` peut transformer des attributs d'image contrôlés par un auteur en balisage actif lors du traitement de la page.
- **Produit :** LiteSpeed Cache for WordPress <= 7.7 ; corrigé en 7.8.
- **Navigateurs :** navigateurs web standards ; la faiblesse est dans la transformation serveur du HTML.
- **Identifiants :** CVE-2026-3129.
- **Plateforme / source d'origine :** LiteSpeed Technologies, signalement Wordfence ; bulletin fournisseur publié le 27 août 2026 et CVE publié le 28 août 2026.
- **Description non destructive :** dans un site de test avec les deux options concernées activées, fournir une balise `<img>` contenant uniquement des valeurs sentinelles autour de `width`/`height`, puis comparer le HTML avant et après la réécriture. Le test doit détecter l'apparition inattendue d'une nouvelle frontière d'attribut ou d'un nouveau nœud sans exécuter de script.
- **Intérêt corpus :** ajouter des cas `HTML input -> regex attribute rewrite -> reparsed HTML`, avec variations de guillemets, ordre des attributs et valeurs limites. Cette famille complète les tests de parser differential en ciblant les transformations textuelles qui précèdent le parsing navigateur.
- **Statut :** `à intégrer`
- **Sources :** https://blog.litespeedtech.com/2026/08/27/security-update-for-lscwp-cve-2026-3129/ ; https://www.cve.org/CVERecord?id=CVE-2026-3129 ; https://vulnerability.circl.lu/vuln/cve-2026-3129

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

- **2026-09-02** — Ajout de deux familles significatives publiées le 1er septembre : league/commonmark (U+000C FORM FEED créant un différentiel entre filtrage d'attributs et parsing HTML) et WPBakery Page Builder (sanitisation appliquée avant décodage Base64, puis rendu brut après changement de représentation).
- **2026-09-01** — Ajout de Helix Ultimate / CVE-2026-78077 : valeurs persistées dans le JSON de MegaMenu rendues dans plusieurs contextes, avec durcissement de l'échappement contextuel et de surfaces voisines dans 2.2.10.
- **2026-08-31** — Ajout de Readest (document `srcdoc` imbriqué survivant à une configuration DOMPurify trop permissive dans un shell Tauri) et SiYuan (métadonnées persistantes de blocs réutilisées dans plusieurs sinks secondaires : hints, backlinks et breadcrumbs).
- **2026-08-30** — Ajout de trois familles : Formwork (`Referer` -> statistiques admin), PrivateBin (MIME contrôlé -> `blob:` same-origin) et LiteSpeed Cache (réécriture regex d'attributs `<img>`). La divergence de versions Formwork entre GHSA et CVE est documentée explicitement.
- **2026-08-28** — Ajout de trois familles significatives : Pocket Android (HTML externe vers WebView avec pont natif), wallabag Android (API vers WebView) et Netron desktop (métadonnées de fichier vers `innerHTML` dans Electron).
- **2026-08-27** — Ajout de CVE-2026-54606 / GHSA-w93q-cq9w-58p7 : réintroduction d'un nœud actif après parsing d'un fragment Embed dans SunEditor.
- **2026-08-26** — Ajout de la recherche PortSwigger du 25 août sur l'utilisation du nom de balise comme source JavaScript / transformation DOM.
- **2026-08-25** — Initialisation du fichier et ajout des premières entrées vérifiées de la veille d'août 2026.