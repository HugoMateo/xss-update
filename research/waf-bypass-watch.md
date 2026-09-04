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

- **2026-09-03** — Initialisation du journal de veille WAF défensive.
- **2026-09-03** — Ajout d'un format de conservation des payloads publiés sous forme neutralisée, avec structure, transformation et traçabilité (hash/référence) sans stocker de chaîne d'évasion directement opérationnelle.
- **2026-09-04** — Ajout de CVE-2026-19949 : injection SQL de second ordre dans All-in-One WP Migration and Backup, retenue comme cas d'angle mort temporel pour les WAF et de divergence entre représentation inspectée et représentation exécutée après transformations applicatives.
