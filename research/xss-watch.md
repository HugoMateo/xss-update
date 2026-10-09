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

## 2026-10 — divulgations et indexations vérifiées

### 2026-10-02 — Basecamp/Fizzy — pagination Turbo vers un blob Active Storage HTML de même origine (HackerOne #3943339)

- **Date de publication :** 2026-10-02 (divulgation publique ; rapport initial 2026-08-16, correction confirmée par Basecamp le 2026-08-28).
- **Date de veille :** 2026-10-09.
- **Famille :** dom-xss, parser-differential, content-type, same-origin-upload, turbo-frame, url-generation.
- **Contexte :** dans Fizzy, des paramètres HTTP non filtrés pouvaient atteindre Rails url_for pour fabriquer une URL de pagination. Un paramètre réservé à la génération d'URL pouvait modifier la destination d'une pagination chargée automatiquement dans une Turbo Frame. Le chemin secondaire aboutissait à un blob Active Storage non attaché, autorisé par une règle trop permissive ; sur le backend S3, un Content-Type HTML paramétré échappait à une comparaison exacte de types dangereux. Turbo interprétait alors la réponse comme HTML et activait les scripts du frame en héritant du nonce CSP de la page. Le fournisseur a confirmé la chaîne et sa correction.
- **Produit :** Fizzy (Basecamp/37signals), démontré sur le commit b12e4c52d8eafee19b0167dc5831138f1cfb7103 ; corrigé en production le 2026-08-28 ; Turbo Rails 2.0.23 dans le rapport. Différence de comportement S3 / Disk signalée.
- **Navigateurs :** Chrome/Chromium dans la reproduction publique ; le rôle du chargement Turbo et de la CSP dépend du frontend.
- **Identifiants :** HackerOne #3943339 ; pas de CVE indiqué.
- **Plateforme / source d'origine :** divulgation HackerOne par pirikara, confirmation et résolution par Basecamp.
- **Description non destructive :** dans une maquette locale à deux comptes fictifs, générer des liens de pagination avec un paramètre réservé remplacé par un chemin de ressource sentinelle ; contrôler la destination effective du Turbo Frame sans insérer de script. Servir un document HTML strictement inerte depuis un stockage de test avec MIME canonique et MIME paramétré, comparer le traitement du Content-Disposition, du Content-Type et de l'autorisation d'un blob non attaché. Ne créer ni jeton, ni appel intercompte, ni requête externe.
- **Intérêt corpus :** chaîne multi-frontières request params -> Rails URL generation -> automatic Turbo pagination -> Active Storage proxy authorization -> MIME exact-match -> HTML frame parser -> CSP nonce handling. Ajouter des assertions indépendantes sur allowlist des paramètres URL, propriété des blobs, canonicalisation MIME et traitement du HTML de même origine ; ne pas reproduire la phase de compromission.
- **Statut :** à intégrer.
- **Sources :** https://hackerone.com/reports/3943339

### 2026-08-31 — Vue SSR — U+000D absent de la validation des noms d'attributs dynamiques (indexé 2026-10-05)

- **Date de publication :** 2026-08-31 (advisory primaire ; indexation GitHub Advisory Database 2026-10-05).
- **Date de veille :** 2026-10-09.
- **Famille :** parser-differential, stored-xss, ssr, attribute-name, control-character.
- **Contexte :** dans @vue/server-renderer, ssrRenderAttrs échappe correctement les valeurs, mais valide les noms de clés dynamiques via une liste de caractères interdits qui omettait U+000D CARRIAGE RETURN. Le parseur HTML normalise CR en LF avant tokenisation, pouvant transformer un nom d'attribut supposé unique en plusieurs attributs distincts dans le HTML SSR. La voie client via setAttribute n'a pas la même faiblesse.
- **Produit :** @vue/server-renderer < 3.5.42 et 3.6.0-rc.0 à 3.6.0-rc.5 ; corrigé en 3.5.42 et 3.6.0-rc.6.
- **Navigateurs :** parseurs HTML conformes WHATWG (normalisation CR/LF) ; cas spécifique au SSR, non au DOM client.
- **Identifiants :** GHSA-g2v6-rqmx-r4w6 ; pas de CVE attribué.
- **Plateforme / source d'origine :** GitHub Security Advisory vuejs/core, signalement onevilx ; recoupement avec correctif et versions publiées.
- **Description non destructive :** injecter uniquement un nom de clé sentinelle de la forme 'champA' + U+000D + 'champB' avec une valeur textuelle neutre, comparer le résultat ssrRenderAttrs, les octets HTML sérialisés et la liste d'attributs du DOM reparsé ; aucun gestionnaire d'événement ni script.
- **Intérêt corpus :** pipeline untrusted object key -> SSR attribute-name validation -> HTML serialization -> CR preprocessing -> attribute tokenization. Contrôler les cinq espaces ASCII définis par HTML et distinguer la validation des clés de celle des valeurs ; comparer SSR et setAttribute.
- **Statut :** à intégrer.
- **Sources :** https://github.com/vuejs/core/security/advisories/GHSA-g2v6-rqmx-r4w6 ; https://github.com/vuejs/core/commit/a2b40db ; https://github.com/vuejs/core/releases/tag/v3.5.42

### 2026-08-25 — ProseMirror < 1.42.3 — attributs du contexte de tranche clipboard sans validation (indexé 2026-10-05)

- **Date de publication :** 2026-08-25 (advisory primaire ; indexation GitHub Advisory Database 2026-10-05).
- **Date de veille :** 2026-10-09.
- **Famille :** dom-xss, rich-text-editor, clipboard, schema-validation, context-reconstruction.
- **Contexte :** lors du collage de HTML provenant d'une source non fiable, le mécanisme de reconstruction du contexte d'une tranche ProseMirror créait des nœuds à partir d'attributs fournis par le clipboard sans appliquer les validateurs du schéma. Le correctif ajoute type.checkAttrs aux attributs du contexte avant de recréer les nœuds.
- **Produit :** prosemirror-view < 1.42.3 ; corrigé en 1.42.3.
- **Navigateurs :** navigateurs web utilisant le composant ProseMirror ; aucun moteur particulier spécifié.
- **Identifiants :** CVE-2026-104847 / GHSA-c8x8-7fp4-3x9w.
- **Plateforme / source d'origine :** advisory ProseMirror, signalement Pedro Paniago (dropn0w), correctif mainteneur.
- **Description non destructive :** coller dans un éditeur de laboratoire un fragment HTML inerte contenant des attributs sentinelles acceptés et refusés par un schéma de test ; vérifier la reconstruction du Slice, les appels de validation d'attributs et le DOM résultant. Ne pas utiliser de script, de gestionnaire d'événement ni de ressource distante.
- **Intérêt corpus :** pipeline external clipboard HTML -> ProseMirror slice context -> node recreation -> schema attribute validation -> editor DOM. Ajouter des variantes pour contextes imbriqués, attributs requis et validateurs qui rejettent, afin de vérifier que toutes les voies de création de nœuds passent par la même politique.
- **Statut :** à intégrer.
- **Sources :** https://github.com/ProseMirror/prosemirror-view/security/advisories/GHSA-c8x8-7fp4-3x9w ; https://github.com/ProseMirror/prosemirror-view/commit/2e91a612bbc1248e55b4f6061fc93fe459f977c1 ; https://github.com/advisories/GHSA-c8x8-7fp4-3x9w

### 2026-09-21 — league/commonmark <= 2.10.1 — fin de chaîne ignorée par le filtre DisallowedRawHtml (indexé 2026-09-30)

- **Date de publication :** 2026-09-21 (advisory primaire ; indexation GitHub Advisory Database 2026-09-30).
- **Date de veille :** 2026-10-09.
- **Famille :** parser-differential, stored-xss, markdown-to-html, regex-boundary, sanitizer.
- **Contexte :** l'extension DisallowedRawHtml cherchait un nom de balise interdit suivi obligatoirement d'un séparateur explicite. Le parseur de blocs Markdown acceptait au contraire un nom de balise interrompu par la fin de la chaîne/l'une des frontières de bloc ; le filtre n'échappait alors pas ce fragment, qui pouvait retrouver une structure HTML différente une fois les blocs assemblés et reparsés par le navigateur. Conditions : html_input=allow et extension DisallowedRawHtml active (GFM).
- **Produit :** league/commonmark >= 1.3.0 et <= 2.10.1 ; corrigé en 2.10.2.
- **Navigateurs :** parseurs HTML standards ; divergence entre regex du renderer Markdown et reconstruction HTML.
- **Identifiants :** GHSA-97jj-33gv-5xf9 ; pas de CVE connu.
- **Plateforme / source d'origine :** advisory thephpleague/commonmark, signalement 4n86rakam1, correctif amont.
- **Description non destructive :** construire une entrée Markdown de test dont le dernier fragment de bloc contient seulement le début d'un nom de balise interdit, sans script ni attribut actif ; comparer le classement du bloc, le résultat du filtre DisallowedRawHtml, la concaténation des blocs et le DOM final. Ajouter un contrôle où le nom est suivi d'un séparateur explicite.
- **Intérêt corpus :** pipeline Markdown partial HTML block -> regex requiring trailing character -> end-of-string omission -> block assembly -> browser HTML parse. Tester systématiquement les fins de chaîne et de bloc dans les règles regex d'interdiction, en plus des séparateurs explicites. Distinct de GHSA-f8fg-pg57-v4j8 (U+000C).
- **Statut :** à intégrer.
- **Sources :** https://github.com/thephpleague/commonmark/security/advisories/GHSA-97jj-33gv-5xf9 ; https://github.com/thephpleague/commonmark/commit/411afcc ; https://github.com/thephpleague/commonmark/releases/tag/2.10.2

### 2026-09-18 — Payload CMS < 3.90.0 — XML et feuille de style servis dans l'origine applicative (indexé 2026-10-07)

- **Date de publication :** 2026-09-18 (advisory primaire ; indexation GitHub Advisory Database 2026-10-07).
- **Date de veille :** 2026-10-09.
- **Famille :** stored-xss, xml, xslt, content-type, upload-to-browser, same-origin.
- **Contexte :** dans certaines configurations de stockage local, un XML téléversé avec une feuille de style associée pouvait être ouvert par un utilisateur connecté et conduire à du JavaScript exécuté dans l'origine de Payload. Les téléversements XML étaient acceptés par défaut. La frontière de confiance est le service de fichiers XML/XSL comme documents interprétables dans l'origine applicative.
- **Produit :** payload < 3.90.0 ; branches canary >= 4.0.0-canary.0 et < 4.0.0-canary.34 ; corrigé en 3.90.0 / 4.0.0-canary.34.
- **Navigateurs :** navigateurs prenant en charge le traitement XML et les feuilles de style dans les conditions concernées ; moteurs précis non indiqués dans l'advisory.
- **Identifiants :** CVE-2026-105868 / GHSA-9qpg-3cf8-w33x.
- **Plateforme / source d'origine :** GitHub Security Advisory payloadcms/payload, signalement Zerotistic ; release corrective.
- **Description non destructive :** téléverser dans une instance isolée un document XML avec une feuille XSL ne produisant que du texte sentinelle. Comparer l'acceptation du fichier, le type MIME, les en-têtes de réponse, l'origine et la représentation finale à l'ouverture ; refuser tout document XML/XSL qui serait interprété comme contenu actif de l'application. Aucun script ni appel réseau.
- **Intérêt corpus :** pipeline XML upload -> local storage -> same-origin serving -> stylesheet processing -> document rendering. Tester l'isolation d'origine et les politiques de livraison sur XML/XSL séparément des SVG, en particulier la différence entre affichage inline et téléchargement.
- **Statut :** à intégrer.
- **Sources :** https://github.com/payloadcms/payload/security/advisories/GHSA-9qpg-3cf8-w33x ; https://github.com/payloadcms/payload/releases/tag/v3.90.0 ; https://github.com/advisories/GHSA-9qpg-3cf8-w33x

### 2026-09-17 — Ghost < 6.64.0 — ressource externe non-image enregistrée comme icône de bookmark (indexé 2026-10-07)

- **Date de publication :** 2026-09-17 (advisory primaire ; indexation GitHub Advisory Database 2026-10-07).
- **Date de veille :** 2026-10-09.
- **Famille :** stored-xss, content-type, remote-fetch, image-metadata, same-origin-upload.
- **Contexte :** la création d'une bookmark card pouvait récupérer une ressource externe et l'enregistrer comme icône ou miniature sans garantir qu'il s'agissait d'une image. Un utilisateur staff, y compris Contributor, pouvait ainsi héberger un document HTML arbitraire dans l'origine du site Ghost. Le problème diffère d'un upload classique : la source est un fetch distant transitant par une fonctionnalité de métadonnées d'aperçu.
- **Produit :** Ghost >= 5.94.0 et < 6.64.0 ; corrigé en 6.64.0.
- **Navigateurs :** navigateurs standards lors de l'ouverture d'une ressource active de même origine ; pas de divergence moteur annoncée.
- **Identifiants :** CVE-2026-105651 / GHSA-347q-26qq-h2p6.
- **Plateforme / source d'origine :** advisory TryGhost/Ghost, signalement VinSOC Labs et chercheurs crédités, correctif amont.
- **Description non destructive :** servir depuis un hôte de laboratoire un document HTML strictement inerte annoncé comme image d'une page de test ; faire créer une bookmark card sur une instance autorisée et comparer type distant déclaré, type détecté, fichier stocké et Content-Type effectivement servi. Vérifier que le document non-image est rejeté ou isolé, sans script ni URL externe à l'environnement de test.
- **Intérêt corpus :** pipeline remote page metadata -> image URL fetch -> media storage -> same-origin file delivery -> browser document interpretation. Couvrir les importeurs d'images indirects (bookmarks, thumbnails, favicons) en plus des uploads directs, avec contrôle du type après récupération et au service.
- **Statut :** à intégrer.
- **Sources :** https://github.com/TryGhost/Ghost/security/advisories/GHSA-347q-26qq-h2p6 ; https://github.com/TryGhost/Ghost/commit/b41fe3f ; https://github.com/TryGhost/Ghost/releases/tag/v6.64.0

---

## 2026-09

### 2026-09-25 — code16/Sharp < 9.22.5 — `data-html-content` franchissant la frontière du sanitizer

- **Famille :** `stored-xss`, `sanitizer-bypass`, `data-attribute`, `editor`, `trust-boundary`
- **Contexte :** dans `SharpEditorFormField`, du contenu contrôlé portant l'attribut `data-html-content` pouvait conserver du HTML qui échappait au chemin normal de sanitisation, puis être stocké et rendu ultérieurement. Le correctif 9.22.5 réserve désormais explicitement ce comportement au mode `RAW_HTML`, qui requiert une sanitisation applicative volontaire.
- **Produit :** code16/Sharp < 9.22.5 ; corrigé en 9.22.5.
- **Navigateurs :** navigateurs web standards ; aucune divergence moteur particulière n'est nécessaire.
- **Identifiants :** CVE-2026-61825 / GHSA-vj3q-vp3g-j9c8.
- **Plateforme / source d'origine :** GitHub Security Advisory code16/Sharp, recoupé avec OSV/GitLab Advisory Database et le correctif amont.
- **Description non destructive :** utiliser un fragment d'éditeur contenant `data-html-content` et uniquement un élément sentinelle inerte. Comparer le DOM d'entrée, la sortie du sanitizer, la représentation persistée et le rendu final. Le test doit échouer si un nœud sentinelle normalement supprimé réapparaît après la frontière `data-html-content`, sans gestionnaire d'événement, script ou ressource externe.
- **Intérêt corpus :** ajouter un pipeline `rich-text DOM -> sanitizer -> privileged data-* carrier -> persistence -> render`. Tester les attributs de métadonnées qui demandent implicitement à une couche ultérieure de réinterpréter une chaîne comme HTML, ainsi que la différence entre mode HTML sûr par défaut et mode RAW explicitement opt-in.
- **Statut :** `à intégrer`
- **Sources :** https://github.com/code16/sharp/security/advisories/GHSA-vj3q-vp3g-j9c8 ; https://github.com/code16/sharp/commit/ec509a22c808a5bd9dfad6a0a85c92ce6f411e21 ; https://osv.dev/vulnerability/GHSA-vj3q-vp3g-j9c8

### 2026-09-24 — xhtml-purifier < 0.4.3 — sanitizer correct avant sérialisation, puis injection à la frontière d'attribut

- **Famille :** `sanitizer-bypass`, `serializer`, `attribute-boundary`, `representation-change`
- **Contexte :** `xhtml-purifier` purifie la structure HTML mais, avant 0.4.3, `attributeString()` concaténait directement certaines valeurs d'attribut dans une chaîne entourée de guillemets doubles sans encodage HTML final. Une valeur pourtant attachée à un attribut autorisé pouvait donc changer la structure du HTML seulement au moment de la sérialisation.
- **Produit :** npm `xhtml-purifier` < 0.4.3 ; corrigé en 0.4.3.
- **Navigateurs :** navigateurs HTML standards ; la faiblesse se produit avant le parsing navigateur et ne dépend pas d'un moteur particulier.
- **Identifiants :** CVE-2026-61784 / GHSA-j8r4-32c5-33rc.
- **Plateforme / source d'origine :** GitHub Security Advisory / GitHub CNA, recoupé avec OSV, le commit correctif et la release 0.4.3.
- **Description non destructive :** placer dans un attribut autorisé une valeur sentinelle contenant un délimiteur de guillemet suivi uniquement d'un attribut neutre. Comparer le modèle purifié avant sérialisation, la chaîne HTML produite puis le DOM reparsé. Le test doit signaler toute création d'un second attribut sans employer d'événement, de script ni d'URL active.
- **Intérêt corpus :** ajouter un pipeline `parse -> sanitize DOM/model -> serialize attributes -> browser reparse` et distinguer explicitement sécurité du modèle interne et sécurité de la représentation sérialisée. Couvrir `class`, `style`, `title`, `alt`, `src` et `href` avec délimiteurs sentinelles, ainsi que les variantes de guillemets et d'encodage.
- **Statut :** `à intégrer`
- **Sources :** https://github.com/cstigler/node-xhtml-purifier/security/advisories/GHSA-j8r4-32c5-33rc ; https://github.com/cstigler/node-xhtml-purifier/commit/21d461ad23e7bc9b3073693d5b51b9b8662044d3 ; https://osv.dev/vulnerability/GHSA-j8r4-32c5-33rc


### 2026-09-11 — Dobase < 2026.06.03 — échappement serveur annulé par `dataset` puis second parsing via `innerHTML`

- **Famille :** `stored-xss`, `dom-xss`, `representation-change`, `dataset`, `innerhtml`, `double-parse`
- **Contexte :** le nom persistant d'un fichier est correctement échappé par ERB lorsqu'il est sérialisé dans un attribut `data-name`. Le navigateur décode ensuite les entités HTML lors de la construction du DOM ; une lecture via `el.dataset.name` récupère donc la valeur textuelle décodée. Cette valeur est finalement interpolée sans nouvel échappement dans deux écritures `innerHTML` du contrôleur Stimulus de la galerie publique, créant un second parsing HTML qui annule la protection appliquée au premier contexte.
- **Produit :** Dobase <= 2026.05.29 ; corrigé en 2026.06.03.
- **Navigateurs :** navigateurs web standards ; la famille repose sur le comportement normal de décodage des attributs HTML par le DOM puis sur un second parsing par `innerHTML`, sans divergence moteur spécifique.
- **Identifiants :** CVE-2026-54165 / GHSA-m95v-4xq6-grhg.
- **Plateforme / source d'origine :** GitHub Security Advisory `smgdkngt/dobase`, publié initialement le 3 juin 2026 et nouvellement indexé comme CVE le 11 septembre 2026 ; recoupé avec le code vulnérable et la version corrigée documentés dans l'advisory primaire.
- **Description non destructive :** utiliser comme nom de fichier une sentinelle contenant uniquement des délimiteurs HTML inoffensifs destinés à produire un nœud neutre. Comparer quatre états : HTML serveur avec entités échappées dans `data-name`, valeur obtenue par `getAttribute`, valeur obtenue par `dataset.name`, puis DOM après le chemin de rendu de la lightbox. Le test doit échouer si la sentinelle, initialement protégée dans l'attribut, devient un nouveau nœud lors de la seconde interprétation ; ne pas employer de gestionnaire d'événement, de script ou de ressource externe.
- **Intérêt corpus :** ajouter un pipeline `untrusted string -> server attribute escaping -> HTML parse/entity decode -> dataset read -> template interpolation -> innerHTML reparse`. Cette famille permet de détecter les protections contextuelles valides à une première frontière mais rendues caduques lorsque la donnée est extraite du DOM puis réutilisée dans un sink de parsing. Généraliser aux attributs `data-*`, aux propriétés DOM qui renvoient des valeurs décodées et aux chaînes transférées d'un contexte attribut vers un contexte HTML.
- **Statut :** `à intégrer`
- **Sources :** https://github.com/smgdkngt/dobase/security/advisories/GHSA-m95v-4xq6-grhg ; https://www.cve.org/CVERecord?id=CVE-2026-54165

### 2026-09-07 — JetBrains YouTrack < 2026.2.18634 — nom d'assigné persisté interprété comme template AngularJS

- **Famille :** `stored-xss`, `client-template-injection`, `angularjs`, `data-to-template`, `secondary-renderer`
- **Contexte :** un nom d'assigné contrôlable et persisté pouvait atteindre une surface de rendu AngularJS où la donnée était interprétée comme contenu de template plutôt que comme texte inerte, conduisant à une XSS stockée. Le point distinctif n'est donc pas une simple insertion HTML : une valeur métier supposée textuelle traverse une frontière `data -> client-side template expression`.
- **Produit :** JetBrains YouTrack < 2026.2.18634 ; corrigé à partir de 2026.2.18634.
- **Navigateurs :** navigateurs web standards exécutant le frontend AngularJS de YouTrack ; aucune divergence de moteur spécifique n'est indiquée par le bulletin public.
- **Identifiants :** CVE-2026-86484.
- **Plateforme / source d'origine :** JetBrains CNA / bulletin « Fixed security issues », recoupé avec l'enregistrement CVE publié le 7 septembre 2026.
- **Description non destructive :** dans une instance de test autorisée, donner à un objet représentant l'assigné une valeur sentinelle contenant uniquement une expression AngularJS inoffensive produisant un texte fixe, puis vérifier séparément la valeur persistée, le texte injecté dans le template et le DOM final. Le test doit échouer dès que la sentinelle est évaluée comme expression au lieu d'être rendue littéralement ; ne pas appeler de fonction, d'API navigateur ou de ressource externe.
- **Intérêt corpus :** ajouter une famille `persistent business field -> AngularJS template compilation/interpolation -> DOM`, distincte des sinks HTML classiques. Tester les champs de nom/libellé supposés textuels lorsqu'ils sont réutilisés dans des templates côté client, et comparer trois états : valeur brute, source de template générée, DOM après compilation. Ajouter une variante de contrôle où les délimiteurs de template doivent rester visibles comme texte, ce qui permet de détecter une régression sans JavaScript actif.
- **Statut :** `à intégrer`
- **Sources :** https://www.jetbrains.com/privacy-security/issues-fixed/ ; https://www.cve.org/CVERecord?id=CVE-2026-86484

### 2026-09-07 — MISP <= 2.5.45 — divergence de parsing d'URL PHP / navigateur dans les widgets Dashboard

- **Famille :** `stored-xss`, `parser-differential`, `url-normalization`, `href`, `dashboard-widget`
- **Contexte :** l'URL d'un Button widget est une configuration persistée contrôlable par un utilisateur. L'ancienne validation acceptait une URL si elle paraissait relative ou si le hostname retourné côté PHP correspondait à l'hôte MISP, sans rejeter certaines formes que le parseur WHATWG du navigateur normalise différemment. Le correctif amont mentionne explicitement les schémas dangereux et les formes contenant des antislashs qui pouvaient atteindre le `href` rendu.
- **Produit :** MISP <= 2.5.45 ; correctif amont dans le commit `adf704e949e6212e1bd22b2af9d124dc6578a399`.
- **Navigateurs :** navigateurs web modernes appliquant les règles de parsing/normalisation d'URL WHATWG ; aucune divergence moteur particulière n'est requise pour la famille de test.
- **Identifiants :** CVE-2026-86440 / GHSA-m9p6-76x3-7vxp.
- **Plateforme / source d'origine :** MISP / CIRCL, signalé par Scottish Government - National Cyber Team ; recoupé avec le commit correctif amont.
- **Description non destructive :** utiliser uniquement des URL sentinelles inertes vers un domaine réservé ou inexistant et comparer quatre états : chaîne brute enregistrée, résultat du parseur URL côté serveur, valeur exacte émise dans `href`, puis URL normalisée par le navigateur. Inclure des variantes avec séparateurs et antislashs sans schéma actif, et considérer le test en échec dès que le navigateur aboutit à une origine ou une structure différente de celle autorisée côté serveur.
- **Intérêt corpus :** ajouter un pipeline `stored URL config -> server-side URL parser/allowlist -> HTML href serialization -> WHATWG browser URL parser`. Couvrir la normalisation des antislashs, caractères de contrôle, formes protocol-relative, différences d'autorité et validation d'origine. Tester aussi la défense en profondeur : validation au handler du widget puis à nouveau au renderer, afin qu'une valeur dangereuse ne puisse pas être réintroduite par un consommateur secondaire.
- **Statut :** `à intégrer`
- **Sources :** https://github.com/MISP/MISP/commit/adf704e949e6212e1bd22b2af9d124dc6578a399 ; https://www.cve.org/CVERecord?id=CVE-2026-86440 ; https://github.com/advisories/GHSA-m9p6-76x3-7vxp

### 2026-09-03 — MapLibre GL JS < 6.4.1 — suppression d'attributs pendant l'itération d'une `NamedNodeMap` live

- **Famille :** `dom-xss`, `sanitizer-bypass`, `live-collection`, `mutation-during-iteration`, `innerhtml`
- **Contexte :** `DOM.sanitize()` parcourt `elem.attributes`, une collection DOM `NamedNodeMap` vivante, tandis que la routine de nettoyage retire des attributs de cette même collection. La suppression décale immédiatement les indices ; lorsque plusieurs attributs à retirer sont adjacents, l'élément suivant peut être sauté et survivre au nettoyage avant insertion via `innerHTML` dans le contrôle d'attribution de la carte.
- **Produit :** MapLibre GL JS < 6.4.1 ; corrigé en 6.4.1.
- **Navigateurs :** navigateurs web standards implémentant les collections DOM vivantes ; le défaut se situe dans l'algorithme de sanitisation côté bibliothèque plutôt que dans une divergence spécifique de moteur.
- **Identifiants :** CVE-2026-85061 / GHSA-jrc7-96c5-q579.
- **Plateforme / source d'origine :** GitHub Security Advisory MapLibre / CVE assigné par GitHub, recoupé avec le correctif, la pull request et la release 6.4.1.
- **Description non destructive :** construire un élément de test comportant plusieurs attributs sentinelles adjacents classés comme interdits par le sanitizer, mais dont les valeurs ne déclenchent aucune action. Comparer la liste statique initiale, la collection `attributes` pendant les suppressions et le DOM obtenu après sanitisation. Le test doit échouer dès qu'un attribut adjacent censé être retiré subsiste, sans utiliser de JavaScript exécutable.
- **Intérêt corpus :** ajouter une famille `live DOM collection -> mutation during indexed iteration -> skipped adjacent node/attribute -> HTML sink`. Généraliser le test aux `NamedNodeMap`, `HTMLCollection` et `NodeList` vivantes lorsqu'une boucle supprime ou déplace les éléments qu'elle parcourt. Vérifier particulièrement les séquences de 2, 3 et N éléments interdits consécutifs, ainsi que la différence entre copie statique préalable et itération directe sur une collection vivante.
- **Statut :** `à intégrer`
- **Sources :** https://github.com/maplibre/maplibre-gl-js/security/advisories/GHSA-jrc7-96c5-q579 ; https://github.com/maplibre/maplibre-gl-js/pull/8189 ; https://github.com/maplibre/maplibre-gl-js/commit/1da69f3cd913a39fa948708e01478663bf48bc27 ; https://github.com/maplibre/maplibre-gl-js/releases/tag/v6.4.1 ; https://www.cve.org/CVERecord?id=CVE-2026-85061

### 2026-09-02 — DiceBear < 9.4.3 — options supposées numériques interpolées sans échappement dans du SVG

- **Famille :** `svg`, `attribute-boundary`, `type-confusion`, `runtime-validation`, `library-output`
- **Contexte :** certaines options exposées comme numériques par les types TypeScript étaient interpolées directement dans des attributs SVG sans échappement XML systématique. Un appelant JavaScript peut néanmoins fournir une chaîne à l'exécution, créant un différentiel entre le contrat statique attendu et la valeur réellement sérialisée.
- **Produit :** `@dicebear/core` et `@dicebear/initials` < 9.4.3 ; corrigés en 9.4.3.
- **Navigateurs :** navigateurs web standards lorsque le SVG généré est inséré inline ou ouvert comme document SVG ; l'impact dépend du contexte de consommation du SVG produit.
- **Identifiants :** CVE-2026-68921 / GHSA-gcr2-9v8m-gq45.
- **Plateforme / source d'origine :** GitHub Security Advisory DiceBear, recoupé avec le commit correctif et la release 9.4.3.
- **Description non destructive :** appeler le générateur dans un environnement de test avec des chaînes sentinelles contenant uniquement des délimiteurs XML inoffensifs à la place d'options normalement numériques, puis comparer la valeur d'option reçue, la chaîne SVG sérialisée et le DOM SVG reparsé. Le test doit signaler toute création d'un nouvel attribut ou nœud, sans introduire de gestionnaire d'événement, de script ou d'URL active.
- **Intérêt corpus :** ajouter une famille `static type says scalar -> runtime accepts string -> direct interpolation -> SVG parse`. Couvrir les options numériques, booléennes ou enum supposées sûres par contrat de type mais non validées au runtime, et tester systématiquement la frontière `library string output -> inline SVG / image/svg+xml document`.
- **Statut :** `à intégrer`
- **Sources :** https://github.com/dicebear/dicebear/security/advisories/GHSA-gcr2-9v8m-gq45 ; https://github.com/dicebear/dicebear/commit/922946d738c4e77ab6c412e27ede75941fec4b59 ; https://github.com/dicebear/dicebear/releases/tag/v9.4.3 ; https://www.cve.org/CVERecord?id=CVE-2026-68921

### 2026-09-02 — BookStack < 26.05.4 — contenu non-image stocké puis servi via une route d'image

- **Famille :** `stored-xss`, `svg`, `content-type`, `upload-to-browser`, `trust-boundary`
- **Contexte :** une route de dessin pouvait conduire au stockage d'un contenu qui n'était pas réellement une image, puis la route de lecture de la galerie le diffusait sans vérifier que le type détecté restait `image/*`. Le correctif centralise le streaming via `DownloadResponseFactory` et refuse les réponses dont le `Content-Type` calculé n'est pas une image.
- **Produit :** BookStack < 26.05.4 ; corrigé en 26.05.4.
- **Navigateurs :** navigateurs web standards ; le risque apparaît lorsqu'une ressource stockée est naviguée/rendue comme contenu actif dans l'origine de l'application.
- **Identifiants :** CVE-2026-84695 / GHSA-r46q-wv4x-rj72.
- **Plateforme / source d'origine :** BookStack Security Release v26.05.4 et commit correctif `ac0348a`, recoupés avec l'advisory GitHub/NVD publié le 2 septembre.
- **Description non destructive :** dans une instance locale, faire passer par le chemin de stockage concerné un contenu sentinelle non-image sans script, puis demander la route de lecture de la galerie et vérifier que la réponse est rejetée au lieu d'être rendue comme document. Comparer extension/nom déclaré, type détecté et `Content-Type` effectivement servi.
- **Intérêt corpus :** ajouter un pipeline `upload/drawing representation -> storage -> gallery stream -> content sniff/type decision -> browser navigation`, et tester séparément validation à l'upload et validation au moment du service. Cette famille couvre les situations où une première couche considère une ressource comme « image » alors qu'une route secondaire la sert avec une sémantique différente.
- **Statut :** `à intégrer`
- **Sources :** https://www.bookstackapp.com/blog/bookstack-release-v26-05-4/ ; https://github.com/BookStackApp/BookStack/commit/ac0348a79f3ddd004ca87703948cb9c7d19a420a ; https://github.com/advisories/GHSA-r46q-wv4x-rj72 ; https://www.cve.org/CVERecord?id=CVE-2026-84695

### 2026-09-01 — enshrined/svg-sanitize <= 0.22.0 — collision sémantique entité DTD XML / référence nommée HTML5

- **Famille :** `stored-xss`, `svg`, `sanitizer-bypass`, `parser-differential`, `xml-to-html`, `representation-change`
- **Contexte :** le sanitizer valide un attribut `href` après résolution d'une entité DTD dans le contexte XML, puis `saveXML()` peut conserver la référence d'entité dans la sortie tout en supprimant le `DOCTYPE`. Lorsque ce SVG assaini est ensuite inséré inline dans une page HTML, le navigateur réinterprète la même référence selon les règles des références de caractères nommées HTML5, ce qui peut produire une valeur d'URL différente de celle réellement validée.
- **Produit :** enshrined/svg-sanitize <= 0.22.0 ; corrigé en 1.0.0 d'après l'advisory primaire.
- **Navigateurs :** exécution confirmée avec Chrome 148 dans l'advisory ; le cas nécessite un SVG rendu inline dans du HTML. Un rendu via `<img src="...svg">` n'est pas affecté par la même mécanique car le document reste parsé comme XML.
- **Identifiants :** GHSA-9rjx-3jch-6vjf ; aucun CVE attribué au moment de la publication.
- **Plateforme / source d'origine :** GitHub Security Advisory darylldoyle/svg-sanitizer, signalé par ExPatch Security Research / Denis Rostilov.
- **Description non destructive :** construire un SVG de test avec une entité DTD dont le nom entre en collision avec une référence de caractère nommée HTML5, mais faire porter l'attribut cible vers une URL sentinelle non active. Comparer trois représentations : valeur vue par le parseur XML pendant la sanitisation, chaîne sérialisée après `saveXML()`, puis valeur effectivement reconstruite dans le DOM HTML après insertion inline. Le test doit uniquement détecter le différentiel de valeur et ne jamais employer de JavaScript exécutable.
- **Intérêt corpus :** ajouter un pipeline `XML parse/entity resolution -> sanitizer validation -> XML serialization/DOCTYPE removal -> HTML5 named-reference resolution -> URL normalization`. Cette famille couvre une classe de bugs où la protection valide une représentation sémantique différente de celle finalement consommée. Tester en priorité les références nommées produisant des caractères d'espacement/contrôle ignorés ou normalisés par les parseurs d'URL, ainsi que la différence `inline SVG` versus ressource SVG externe.
- **Statut :** `à intégrer`
- **Sources :** https://github.com/darylldoyle/svg-sanitizer/security/advisories/GHSA-9rjx-3jch-6vjf ; https://github.com/darylldoyle/svg-sanitizer/security/advisories

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

- **2026-10-09** — Ajout de 6 cas dédupliqués et non destructifs : Basecamp/Fizzy HackerOne #3943339 (pagination Turbo + blob Active Storage/MIME), Vue SSR GHSA-g2v6-rqmx-r4w6 (CR dans nom d'attribut), ProseMirror CVE-2026-104847 (contexte clipboard non validé), CommonMark GHSA-97jj-33gv-5xf9 (frontière fin de chaîne du filtre raw HTML), Payload CVE-2026-105868 (XML/XSL same-origin) et Ghost CVE-2026-105651 (bookmark remote-fetch non-image). Les dates primaires et d'indexation sont distinguées.

- **2026-09-29** — Ajout de CVE-2026-61784 / GHSA-j8r4-32c5-33rc (xhtml-purifier : rupture de frontière d'attribut lors de la sérialisation après sanitisation) et CVE-2026-61825 / GHSA-vj3q-vp3g-j9c8 (Sharp : `data-html-content` comme transport privilégié de HTML à travers le sanitizer).

- **2026-09-15** — Ajout de CVE-2026-54165 / GHSA-m95v-4xq6-grhg : Dobase, échappement correct dans un attribut `data-*` puis décodage par le DOM et réinjection de la valeur via `innerHTML`, retenu comme famille `server attribute escape -> DOM decode -> dataset -> innerHTML reparse`.
- **2026-09-09** — Ajout de CVE-2026-86440 / GHSA-m9p6-76x3-7vxp : MISP Dashboard Button widget, divergence entre validation/parsing d'URL côté PHP et normalisation WHATWG du navigateur, notamment autour des antislashs et des schémas, retenue comme famille `stored URL -> server parser -> href -> browser parser`.
- **2026-09-08** — Ajout de CVE-2026-86484 : XSS stockée dans JetBrains YouTrack via interprétation AngularJS d'un nom d'assigné persisté, retenue comme famille `business data -> client-side template expression -> DOM`.
- **2026-09-05** — Ajout de deux familles publiées le 2 septembre : DiceBear / CVE-2026-68921 (contrat de type statique numérique contournable à l'exécution puis interpolation directe dans du SVG) et BookStack / CVE-2026-84695 (contenu non-image stocké puis servi via une route de galerie sans validation finale suffisante du type de contenu).
- **2026-09-04** — Ajout de CVE-2026-85061 / GHSA-jrc7-96c5-q579 : bypass de sanitizer MapLibre GL JS causé par la suppression d'attributs pendant l'itération indexée d'une `NamedNodeMap` live, pouvant faire sauter un attribut interdit adjacent.
- **2026-09-03** — Ajout de GHSA-9rjx-3jch-6vjf : collision sémantique entre résolution d'entités DTD en XML pendant la sanitisation SVG et références de caractères nommées HTML5 après sérialisation et insertion inline.
- **2026-09-02** — Ajout de deux familles significatives publiées le 1er septembre : league/commonmark (U+000C FORM FEED créant un différentiel entre filtrage d'attributs et parsing HTML) et WPBakery Page Builder (sanitisation appliquée avant décodage Base64, puis rendu brut après changement de représentation).
- **2026-09-01** — Ajout de Helix Ultimate / CVE-2026-78077 : valeurs persistées dans le JSON de MegaMenu rendues dans plusieurs contextes, avec durcissement de l'échappement contextuel et de surfaces voisines dans 2.2.10.
- **2026-08-31** — Ajout de Readest (document `srcdoc` imbriqué survivant à une configuration DOMPurify trop permissive dans un shell Tauri) et SiYuan (métadonnées persistantes de blocs réutilisées dans plusieurs sinks secondaires : hints, backlinks et breadcrumbs).
- **2026-08-30** — Ajout de trois familles : Formwork (`Referer` -> statistiques admin), PrivateBin (MIME contrôlé -> `blob:` same-origin) et LiteSpeed Cache (réécriture regex d'attributs `<img>`). La divergence de versions Formwork entre GHSA et CVE est documentée explicitement.
- **2026-08-28** — Ajout de trois familles significatives : Pocket Android (HTML externe vers WebView avec pont natif), wallabag Android (API vers WebView) et Netron desktop (métadonnées de fichier vers `innerHTML` dans Electron).
- **2026-08-27** — Ajout de CVE-2026-54606 / GHSA-w93q-cq9w-58p7 : réintroduction d'un nœud actif après parsing d'un fragment Embed dans SunEditor.
- **2026-08-26** — Ajout de la recherche PortSwigger du 25 août sur l'utilisation du nom de balise comme source JavaScript / transformation DOM.
- **2026-08-25** — Initialisation du fichier et ajout des premières entrées vérifiées de la veille d'août 2026.
