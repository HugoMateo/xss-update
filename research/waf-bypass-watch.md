# WAF Bypass Watch

Journal de veille défensive sur les techniques publiques de contournement de WAF utiles à des tests de sécurité autorisés.

## Périmètre et règles

- Ne conserver que des techniques publiques, vérifiables et pertinentes pour l'amélioration de règles défensives.
- Décrire les classes de contournement, causes racines, normalisations et différences de parsing.
- Lorsqu'une source publique contient un payload opérationnel, ne pas le recopier tel quel : conserver une **version neutralisée** avec marqueurs sûrs, la **structure/transformation exacte**, le **contexte**, la **source primaire** et, si possible, un **hash** ou identifiant du payload publié pour la traçabilité.
- Les variantes neutralisées doivent rester suffisantes pour des tests de régression en laboratoire sans constituer une chaîne d'évasion prête à l'emploi.
- Privilégier les sources primaires : recherches de chercheurs, PortSwigger, advisories fournisseurs, CVE/GHSA, plateformes de bug bounty avec divulgation publique et rapports techniques.
- Recouper les informations importantes lorsqu'une technique est reprise ailleurs.
- Dédupliquer par identifiant public ou, à défaut, par famille technique + source primaire.
- Statuts : `nouveau`, `à reproduire`, `intégré`, `archivé`.

## Schéma d'une entrée

```yaml
date_publication: YYYY-MM-DD
date_veille: YYYY-MM-DD
famille: normalization | parser-differential | encoding | protocol | request-smuggling-adjacent | content-type | autre
produit_waf: nom/version si applicable
contexte: description courte
identifiants: []
plateforme_source: nom
payload_neutralise: description ou gabarit avec marqueurs sûrs
payload_hash_ou_reference: valeur si disponible
transformation: description exacte de la normalisation/encodage/parsing
statut: nouveau
source: URL
```

## Axes de classification

- Canonicalisation et double décodage.
- Différences de parsing entre WAF, proxy, serveur et application.
- Encodages URL/Unicode/HTML et normalisation de caractères.
- Ambiguïtés de `Content-Type`, multipart, JSON, XML et formulaires.
- Variantes de chemin, séparateurs, paramètres et ordre des transformations.
- HTTP/1.1, HTTP/2, HTTP/3 et écarts de représentation pertinents pour l'inspection.
- Transformations spécifiques à un framework ou middleware.

---

## Entrées

### 2026-09-27 — CVE-2026-61812 — t:htmlEntityDecode ne reconnaissait que cinq entités nommées,

```yaml
date_publication: 2026-09-27
date_veille: 2026-10-10
famille: encoding
produit_waf: "ModSecurity 2 <=2.9.14 / 3 <=3.0.16"
contexte: "t:htmlEntityDecode ne reconnaissait que cinq entités nommées, avec une collision de préfixe supplémentaire en v3"
identifiants: [CVE-2026-61812, GHSA-cxqf-vgrr-xxrv]
plateforme_source: ModSecurity / GitHub Security Advisory
payload_neutralise: "comparer les entités ASCII HTML nommées appliquées à une sentinelle inerte et leur décodage WHATWG"
payload_hash_ou_reference: GHSA-cxqf-vgrr-xxrv
transformation: "t:htmlEntityDecode ne reconnaissait que cinq entités nommées, avec une collision de préfixe supplémentaire en v3"
statut: nouveau
source: https://github.com/owasp-modsecurity/ModSecurity/security/advisories/GHSA-cxqf-vgrr-xxrv
```

**Cause racine.** t:htmlEntityDecode ne reconnaissait que cinq entités nommées, avec une collision de préfixe supplémentaire en v3.

**Impact défensif.** comparer les entités ASCII HTML nommées appliquées à une sentinelle inerte et leur décodage WHATWG. Vérifier la parité entre représentation inspectée et consommée ; mettre à jour vers libmodsecurity3 3.0.17 ou mod_security2 2.9.15 selon les versions affectées.

**Sources.** https://github.com/owasp-modsecurity/ModSecurity/security/advisories/GHSA-cxqf-vgrr-xxrv ; https://modsecurity.org/20260928/security-update-digest-overview-of-recent-advisory-fixes-2026-september/


### 2026-09-27 — CVE-2026-104269 — multipart filename* RFC 2231 ignoré ou non

```yaml
date_publication: 2026-09-27
date_veille: 2026-10-10
famille: parser-differential
produit_waf: "ModSecurity 2 <=2.9.14 / 3 <=3.0.16"
contexte: "multipart filename* RFC 2231 ignoré ou non prioritaire face à filename alors que le backend peut le privilégier"
identifiants: [CVE-2026-104269, GHSA-5pww-8rfg-9crf]
plateforme_source: ModSecurity / GitHub Security Advisory
payload_neutralise: "utiliser deux noms de fichiers sentinelles distincts et comparer la valeur exposée aux règles et au backend"
payload_hash_ou_reference: GHSA-5pww-8rfg-9crf
transformation: "multipart filename* RFC 2231 ignoré ou non prioritaire face à filename alors que le backend peut le privilégier"
statut: nouveau
source: https://github.com/owasp-modsecurity/ModSecurity/security/advisories/GHSA-5pww-8rfg-9crf
```

**Cause racine.** multipart filename* RFC 2231 ignoré ou non prioritaire face à filename alors que le backend peut le privilégier.

**Impact défensif.** utiliser deux noms de fichiers sentinelles distincts et comparer la valeur exposée aux règles et au backend. Vérifier la parité entre représentation inspectée et consommée ; mettre à jour vers libmodsecurity3 3.0.17 ou mod_security2 2.9.15 selon les versions affectées.

**Sources.** https://github.com/owasp-modsecurity/ModSecurity/security/advisories/GHSA-5pww-8rfg-9crf ; https://modsecurity.org/20260928/security-update-digest-overview-of-recent-advisory-fixes-2026-september/


### 2026-09-27 — CVE-2026-104259 — t:removeComments sautait le caractère suivant une fermeture

```yaml
date_publication: 2026-09-27
date_veille: 2026-10-10
famille: normalization
produit_waf: "ModSecurity 2 <=2.9.14 / 3 <=3.0.16"
contexte: "t:removeComments sautait le caractère suivant une fermeture de commentaire, causant conservation de commentaires adjacents, NUL final ou troncature"
identifiants: [CVE-2026-104259, GHSA-qrch-pjfr-9g47]
plateforme_source: ModSecurity / GitHub Security Advisory
payload_neutralise: "tester des mots sentinelles séparés par commentaires adjacents et vérifier sortie complète sans NUL"
payload_hash_ou_reference: GHSA-qrch-pjfr-9g47
transformation: "t:removeComments sautait le caractère suivant une fermeture de commentaire, causant conservation de commentaires adjacents, NUL final ou troncature"
statut: nouveau
source: https://github.com/owasp-modsecurity/ModSecurity/security/advisories/GHSA-qrch-pjfr-9g47
```

**Cause racine.** t:removeComments sautait le caractère suivant une fermeture de commentaire, causant conservation de commentaires adjacents, NUL final ou troncature.

**Impact défensif.** tester des mots sentinelles séparés par commentaires adjacents et vérifier sortie complète sans NUL. Vérifier la parité entre représentation inspectée et consommée ; mettre à jour vers libmodsecurity3 3.0.17 ou mod_security2 2.9.15 selon les versions affectées.

**Sources.** https://github.com/owasp-modsecurity/ModSecurity/security/advisories/GHSA-qrch-pjfr-9g47 ; https://modsecurity.org/20260928/security-update-digest-overview-of-recent-advisory-fixes-2026-september/


### 2026-09-27 — CVE-2026-73856 — SecResponseBodyMimeType comparait Content-Type de réponse avec sensibilité

```yaml
date_publication: 2026-09-27
date_veille: 2026-10-10
famille: content-type
produit_waf: "libmodsecurity3 <=3.0.16"
contexte: "SecResponseBodyMimeType comparait Content-Type de réponse avec sensibilité à la casse et omettait certaines inspections"
identifiants: [CVE-2026-73856, GHSA-vmg8-j66p-vgvw]
plateforme_source: ModSecurity / GitHub Security Advisory
payload_neutralise: "réponse de laboratoire textuelle inerte avec variations de casse de Content-Type et comparaison de l'activation RESPONSE_BODY"
payload_hash_ou_reference: GHSA-vmg8-j66p-vgvw
transformation: "SecResponseBodyMimeType comparait Content-Type de réponse avec sensibilité à la casse et omettait certaines inspections"
statut: nouveau
source: https://github.com/owasp-modsecurity/ModSecurity/security/advisories/GHSA-vmg8-j66p-vgvw
```

**Cause racine.** SecResponseBodyMimeType comparait Content-Type de réponse avec sensibilité à la casse et omettait certaines inspections.

**Impact défensif.** réponse de laboratoire textuelle inerte avec variations de casse de Content-Type et comparaison de l'activation RESPONSE_BODY. Vérifier la parité entre représentation inspectée et consommée ; mettre à jour vers libmodsecurity3 3.0.17 ou mod_security2 2.9.15 selon les versions affectées.

**Sources.** https://github.com/owasp-modsecurity/ModSecurity/security/advisories/GHSA-vmg8-j66p-vgvw ; https://modsecurity.org/20260928/security-update-digest-overview-of-recent-advisory-fixes-2026-september/


### 2026-09-27 — CVE-2026-103932 — @rxGlobal sous PCRE2 traitait le dépassement de

```yaml
date_publication: 2026-09-27
date_veille: 2026-10-10
famille: autre
produit_waf: "libmodsecurity3 3.0.5–3.0.16"
contexte: "@rxGlobal sous PCRE2 traitait le dépassement de limite comme une absence de correspondance et ne validait pas certains motifs dynamiques"
identifiants: [CVE-2026-103932, GHSA-5m93-4h75-3p2w]
plateforme_source: ModSecurity / GitHub Security Advisory
payload_neutralise: "mesurer sur un motif synthétique borné les états erreur/limite/no-match et la télémétrie de contrôle"
payload_hash_ou_reference: GHSA-5m93-4h75-3p2w
transformation: "@rxGlobal sous PCRE2 traitait le dépassement de limite comme une absence de correspondance et ne validait pas certains motifs dynamiques"
statut: nouveau
source: https://github.com/owasp-modsecurity/ModSecurity/security/advisories/GHSA-5m93-4h75-3p2w
```

**Cause racine.** @rxGlobal sous PCRE2 traitait le dépassement de limite comme une absence de correspondance et ne validait pas certains motifs dynamiques.

**Impact défensif.** mesurer sur un motif synthétique borné les états erreur/limite/no-match et la télémétrie de contrôle. Vérifier la parité entre représentation inspectée et consommée ; mettre à jour vers libmodsecurity3 3.0.17 ou mod_security2 2.9.15 selon les versions affectées.

**Sources.** https://github.com/owasp-modsecurity/ModSecurity/security/advisories/GHSA-5m93-4h75-3p2w ; https://modsecurity.org/20260928/security-update-digest-overview-of-recent-advisory-fixes-2026-september/


### 2026-09-27 — GHSA-4j47-8qcr-jf59 — t:base64DecodeExt gérait incorrectement l'alphabet Base64URL et certains

```yaml
date_publication: 2026-09-27
date_veille: 2026-10-10
famille: encoding
produit_waf: "ModSecurity 2 <=2.9.14 / 3 <=3.0.16"
contexte: "t:base64DecodeExt gérait incorrectement l'alphabet Base64URL et certains groupes de padding malformés"
identifiants: [GHSA-4j47-8qcr-jf59]
plateforme_source: ModSecurity / GitHub Security Advisory
payload_neutralise: "encoder une sentinelle inerte en Base64URL et comparer sortie du décodeur à RFC 4648, sans contenu actif"
payload_hash_ou_reference: GHSA-4j47-8qcr-jf59
transformation: "t:base64DecodeExt gérait incorrectement l'alphabet Base64URL et certains groupes de padding malformés"
statut: nouveau
source: https://github.com/owasp-modsecurity/ModSecurity/security/advisories/GHSA-4j47-8qcr-jf59
```

**Cause racine.** t:base64DecodeExt gérait incorrectement l'alphabet Base64URL et certains groupes de padding malformés.

**Impact défensif.** encoder une sentinelle inerte en Base64URL et comparer sortie du décodeur à RFC 4648, sans contenu actif. Vérifier la parité entre représentation inspectée et consommée ; mettre à jour vers libmodsecurity3 3.0.17 ou mod_security2 2.9.15 selon les versions affectées.

**Sources.** https://github.com/owasp-modsecurity/ModSecurity/security/advisories/GHSA-4j47-8qcr-jf59 ; https://modsecurity.org/20260928/security-update-digest-overview-of-recent-advisory-fixes-2026-september/


### 2026-09 — Envoy — segments dot/dotdot avec paramètres de chemin

```yaml
date_publication: 2026-09
date_veille: 2026-10-09
famille: normalization
produit_waf: "Envoy proxy, versions corrigées 1.39.1 / 1.38.4 / 1.37.6 / 1.36.10"
contexte: "normalisation d'URL ne reconnaissant pas les paramètres de segment RFC 3986 sur des segments dot/dotdot ; l'amont peut interpréter un chemin canonique différent"
identifiants: [GHSA-2w8w-rfw7-8gg4]
plateforme_source: GitHub Security Advisory / fournisseur
payload_neutralise: "comparer dans un laboratoire des chemins sentinelles contenant un segment relatif muni d'un paramètre fictif, et relever chemin vu par Envoy, route sélectionnée et chemin canonique côté backend ; aucun endpoint sensible"
payload_hash_ou_reference: GHSA-2w8w-rfw7-8gg4
transformation: "normalisation d'URL ne reconnaissant pas les paramètres de segment RFC 3986 sur des segments dot/dotdot ; l'amont peut interpréter un chemin canonique différent"
statut: nouveau
source: https://github.com/envoyproxy/envoy/security/advisories/GHSA-2w8w-rfw7-8gg4
```

**Cause racine.** normalisation d'URL ne reconnaissant pas les paramètres de segment RFC 3986 sur des segments dot/dotdot ; l'amont peut interpréter un chemin canonique différent.

**Impact défensif.** Tester la cohérence de canonicalisation et de RBAC entre proxy et application ; aligner normalisation et règles de routage.

**Sources.** https://github.com/envoyproxy/envoy/security/advisories/GHSA-2w8w-rfw7-8gg4


### 2026-10-08 — Coraza < 3.8.0 — décodage octal JavaScript incorrect

```yaml
date_publication: 2026-10-08
date_veille: 2026-10-09
famille: encoding
produit_waf: "Coraza WAF >=3.0.0 <3.8.0"
contexte: "t:jsDecode inclut par erreur l'antislash dans le tampon numérique octal ; ParseInt échoue et produit un octet NUL plutôt que le caractère attendu"
identifiants: [CVE-2026-104774]
plateforme_source: GitHub Security Advisory / fournisseur
payload_neutralise: "utiliser une échappement octal représentant uniquement une lettre sentinelle inerte et comparer décodage JavaScript de référence, sortie t:jsDecode et décision de règle ; aucune syntaxe active"
payload_hash_ou_reference: GHSA-pc5q-qfxp-ggqv
transformation: "t:jsDecode inclut par erreur l'antislash dans le tampon numérique octal ; ParseInt échoue et produit un octet NUL plutôt que le caractère attendu"
statut: nouveau
source: https://github.com/corazawaf/coraza/security/advisories/GHSA-pc5q-qfxp-ggqv
```

**Cause racine.** t:jsDecode inclut par erreur l'antislash dans le tampon numérique octal ; ParseInt échoue et produit un octet NUL plutôt que le caractère attendu.

**Impact défensif.** Contrôler la parité de décodage des échappements octaux, les erreurs de conversion et l'absence de NUL inattendu. Correctif 3.8.0.

**Sources.** https://github.com/corazawaf/coraza/security/advisories/GHSA-pc5q-qfxp-ggqv


### 2026-10-04 — JavaScript à identifiants cunéiformes — obfuscation Unicode et coercions implicites contre inspection lexicale WAF

```yaml
date_publication: 2026-10-04
date_veille: 2026-10-04
famille: encoding
produit_waf: WAF/filtres XSS fondés sur signatures lexicales ASCII ou tokenisation Unicode incomplète
contexte: payload JavaScript public utilisant des caractères cunéiformes Unicode comme identifiants valides et reconstruisant dynamiquement des chaînes à partir de coercions JavaScript, afin de réduire la présence de mots-clés ASCII caractéristiques dans la représentation inspectée
identifiants: []
plateforme_source: X / publication publique fournie par l'utilisateur
payload_neutralise: même graphe d'affectations avec identifiants cunéiformes et mêmes primitives de coercion, mais terminaison remplacée par <SENTINELLE_INERTE> ; vérifier uniquement la chaîne reconstruite
payload_hash_ou_reference: X status 2105654858015457541
transformation: source Unicode -> tokenisation ECMAScript des identifiants non-ASCII -> coercions implicites booléen/objet vers chaînes -> extraction de caractères par index -> concaténation dynamique -> résolution de propriété calculée ; étape d'exécution terminale supprimée du cas de régression
statut: nouveau
source: https://x.com/i/status/2105654858015457541
```

**Cause racine.** Un filtre fondé principalement sur des mots-clés, noms de variables ou motifs ASCII peut sous-estimer un programme JavaScript valide dont les identifiants proviennent d'autres blocs Unicode. La reconstruction de chaînes par coercions natives et indexation signifie aussi que les jetons significatifs n'existent pas nécessairement sous forme contiguë dans la requête inspectée. La technique relève d'un écart entre détection lexicale et sémantique ECMAScript.

**Impact défensif.** Ajouter une famille de tests `Unicode identifier -> ECMAScript tokenization -> implicit coercion -> character extraction -> computed property`, en conservant les identifiants cunéiformes mais en arrêtant le programme avant tout sink exécutable. Comparer représentation brute, tokens d'un parseur ECMAScript et chaîne sentinelle reconstruite.

**Source.** X status `2105654858015457541`, fourni directement pour intégration au corpus : https://x.com/i/status/2105654858015457541


### 2026-09-17 — Quarkus — désaccord de normalisation des chemins

```yaml
date_publication: 2026-09-17
date_veille: 2026-10-09
famille: parser-differential
produit_waf: contrôles de chemin en amont de Quarkus ; aucun WAF spécifique confirmé vulnérable
contexte: le composant d'autorisation et le routeur HTTP ne normalisent pas toujours le chemin de façon identique
identifiants: [CVE-2026-87743, GHSA-pw2v-hfg7-72m6]
plateforme_source: Red Hat Product Security
payload_neutralise: deux chemins factices de laboratoire, sans endpoint sensible, pour comparer la décision de politique et le handler final
payload_hash_ou_reference: CVE-2026-87743
transformation: représentation du chemin à l'entrée -> contrôle d'autorisation -> routage ; divergence de représentation canonique
statut: nouveau
source: https://access.redhat.com/security/cve/CVE-2026-87743
```

**Cause racine.** Une divergence entre les représentations de chemin utilisées par les règles d'accès et le dispatcher HTTP. Le bulletin public ne documente pas les octets exacts qui déclenchent le défaut.

**Impact défensif.** Comparer en laboratoire les décisions d'autorisation et la destination finale de chemins sentinelles, et imposer une canonicalisation cohérente avant toute décision de sécurité. Il s'agit d'une famille pertinente pour les politiques WAF/edge, sans preuve d'une faille dans un WAF particulier.

**Sources.** https://access.redhat.com/security/cve/CVE-2026-87743 ; https://www.ibm.com/support/pages/node/7289050
### 2026-09-07 — ash_authentication_oauth2_server < 0.3.1 — alias de chemin contournant des contrôles edge ciblés

```yaml
date_publication: 2026-09-07
date_veille: 2026-09-08
famille: protocol
produit_waf: WAF, rate limits et contrôles edge appliqués par préfixe de chemin
contexte: le même sous-routeur OAuth était monté sous un préfixe canonique et sous un préfixe alternatif normalement réservé à la découverte ; le framework retire le préfixe avant dispatch, rendant les mêmes routes internes accessibles sous les deux montages
identifiants:
  - CVE-2026-82754
  - GHSA-wwxg-h779-3wf4
plateforme_source: Erlang Ecosystem Foundation CNA / GitHub Security Advisory ash-project
payload_neutralise: requêtes de laboratoire vers <PREFIXE_CANONIQUE>/<ENDPOINT_SENTINELLE> puis <PREFIXE_ALTERNATIF>/<ENDPOINT_SENTINELLE>, avec corps inerte et aucune opération OAuth réelle ; vérifier uniquement si les deux chemins atteignent le même handler et reçoivent des politiques edge différentes
payload_hash_ou_reference: CVE-2026-82754 ; GHSA-wwxg-h779-3wf4
transformation: requête HTTP -> matching du préfixe externe -> suppression du préfixe par Phoenix forward -> dispatch dans le même ProtocolRouter -> route interne identique ; si le WAF/rate-limit/auth exemption est attaché uniquement au préfixe canonique, l'alias alternatif contourne la portée de la politique
statut: nouveau
source: https://github.com/ash-project/ash_authentication_oauth2_server/security/advisories/GHSA-wwxg-h779-3wf4
```

**Cause racine.** `oauth2_server_protocol_routes/1` montait le même `ProtocolRouter` sous deux préfixes. Comme `Phoenix.forward` retire le préfixe correspondant avant de déléguer au sous-routeur, l'ensemble de la table de routes internes devenait accessible depuis les deux espaces de chemin. Des protections edge écrites uniquement pour le chemin canonique, ou des règles permissives appliquées au préfixe alternatif, pouvaient donc ne pas s'appliquer à la route équivalente.

**Impact défensif.** Ajouter une famille de tests `canonical path -> alternate mount -> same backend handler -> policy mismatch`. Pour chaque route sensible, comparer le handler atteint, le statut WAF, le rate-limit, l'authentification et la journalisation sous tous les préfixes/alias exposés par le framework. Les contrôles doivent être attachés à la sémantique de la route finale ou normaliser les alias avant décision, plutôt que dépendre uniquement d'une chaîne de chemin externe.

**Version corrigée.** `ash_authentication_oauth2_server` 0.3.1. Le correctif limite le montage alternatif aux seuls documents de découverte et renvoie 404 pour les autres routes.

**Sources.**
- GitHub Security Advisory, 2026-09-07: https://github.com/ash-project/ash_authentication_oauth2_server/security/advisories/GHSA-wwxg-h779-3wf4
- Erlang Ecosystem Foundation CNA, 2026-09-07: https://cna.erlef.org/cves/CVE-2026-82754.html

### 2026-09-01 — All-in-One WP Migration and Backup <= 7.109 — injection SQL de second ordre / angle mort temporel WAF

```yaml
date_publication: 2026-09-01
date_veille: 2026-09-04
famille: autre
produit_waf: WAF HTTP classiques ; règle de mitigation Wordfence déployée aux offres Premium/Care/Response le 2026-08-16
contexte: donnée non fiable acceptée par une requête initiale puis persistée, transformée et réinterprétée ultérieurement pendant un cycle export/restauration
identifiants:
  - CVE-2026-19949
plateforme_source: Wordfence Bug Bounty Program / Wordfence Research
payload_neutralise: deux entrées trackback de laboratoire contenant uniquement des marqueurs inertes ; l'une termine un champ texte par un marqueur d'échappement neutralisé, l'autre place un jeton sentinelle dans le champ URL afin d'observer les changements de frontières de chaîne sans exécuter de SQL
payload_hash_ou_reference: CVE-2026-19949 ; publication primaire Wordfence du 2026-09-01
transformation: entrée HTTP -> stockage dans la table de commentaires -> export SQL qui double correctement l'antislash final -> restauration -> regex de détection des littéraux ne vérifiant qu'un seul octet avant l'apostrophe de fermeture -> mauvaise interprétation d'une séquence d'antislashs de longueur paire -> sur-capture du littéral suivant -> cycle unescape / remplacement d'URL / re-escape -> modification de la frontière de chaîne dans le SQL reconstruit
statut: nouveau
source: https://www.wordfence.com/blog/2026/09/5-million-wordpress-sites-affected-by-sql-injection-vulnerability-in-all-in-one-wp-migration-and-backup-wordpress-plugin/
```

**Cause racine.** Le WAF voit la requête au moment de l'entrée, alors que le comportement dangereux n'apparaît qu'après persistance puis plusieurs transformations internes. Le défaut applicatif provient d'une regex qui traite incorrectement la parité d'une séquence d'antislashs avant une apostrophe de fermeture pendant la restauration de l'archive.

**Impact défensif.** Ajouter aux tests WAF des scénarios de second ordre où la décision de sécurité doit être corrélée avec les transformations ultérieures de l'application. Les tests doivent comparer la représentation reçue, stockée, exportée et finalement consommée, et signaler tout changement de frontière syntaxique. Une simple détection de signatures SQL sur la requête initiale n'est pas suffisante pour cette famille.

**Version corrigée.** All-in-One WP Migration and Backup 7.110. Le changelog WordPress.org mentionne explicitement le correctif relatif aux valeurs se terminant par un antislash et crédite le chercheur Jack Taylor.

**Sources.**
- Wordfence Research / Bug Bounty Program, 2026-09-01: https://www.wordfence.com/blog/2026/09/5-million-wordpress-sites-affected-by-sql-injection-vulnerability-in-all-in-one-wp-migration-and-backup-wordpress-plugin/
- WordPress.org, changelog 7.110: https://wordpress.org/plugins/all-in-one-wp-migration/

---

## Journal de mise à jour

- **2026-10-10** — Rattrapage de six advisories ModSecurity de septembre 2026 : HTML entities, multipart RFC 2231, commentaires adjacents, Content-Type, PCRE2 @rxGlobal et Base64URL ; cas neutralisés et dédupliqués.

- **2026-10-09** — Ajout des cas Coraza CVE-2026-104774 (décodage octal `jsDecode`) et Envoy GHSA-2w8w-rfw7-8gg4 (paramètres sur segments relatifs et normalisation des chemins), sous forme de régressions inertes.

- **2026-10-09** — Quarkus CVE-2026-87743 : divergence de canonicalisation entre règle d'autorisation et routage HTTP, conservée comme cas de régression edge non destructif.
- **2026-10-04** — Ajout du cas public X `2105654858015457541` : obfuscation JavaScript par identifiants cunéiformes Unicode et reconstruction de chaînes via coercions/indexation. La terminaison exécutable a été neutralisée ; le corpus conserve la structure lexicale et les transformations pour régression WAF.

- **2026-09-03** — Initialisation du journal de veille WAF défensive.
- **2026-09-03** — Ajout d'un format de conservation des payloads publiés sous forme neutralisée, avec structure, transformation et traçabilité (hash/référence) sans stocker de chaîne d'évasion directement opérationnelle.
- **2026-09-04** — Ajout de CVE-2026-19949 : injection SQL de second ordre dans All-in-One WP Migration and Backup, retenue comme cas d'angle mort temporel pour les WAF et de divergence entre représentation inspectée et représentation exécutée après transformations applicatives.
- **2026-09-08** — Ajout de CVE-2026-82754 / GHSA-wwxg-h779-3wf4 : alias de préfixe créé par un montage de sous-routeur Phoenix, permettant à une route sensible d'atteindre le même handler sous un chemin alternatif et de sortir du périmètre de contrôles WAF/rate-limit définis uniquement sur le chemin canonique.
