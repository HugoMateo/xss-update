# WAF Bypass Watch

Journal de veille défensive sur les techniques publiques de contournement de WAF utiles à des tests de sécurité autorisés.

## Périmètre et règles

- Ne conserver que des techniques publiques, vérifiables et pertinentes pour l'amélioration de règles défensives.
- Décrire les classes de contournement, causes racines, normalisations et différences de parsing sans archiver de payloads d'évasion prêts à l'emploi.
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

## Journal de mise à jour

- **2026-09-03** — Initialisation du journal de veille WAF défensive.
