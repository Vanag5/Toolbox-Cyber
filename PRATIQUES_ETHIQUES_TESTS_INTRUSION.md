# Manuel de Bonnes Pratiques pour les Tests d'Intrusion — Toolbox Cyber

## 1. Introduction

Ce manuel présente les bonnes pratiques à suivre pour effectuer des tests d'intrusion dans le cadre du projet Toolbox Cyber. L'objectif est de garantir des tests efficaces, éthiques et sécurisés.

## 2. Portée et autorisations

- **Portée** : limiter les tests aux composants du projet (API Flask, base PostgreSQL, stockage Minio, services Redis et Celery, scans ZAP).
- **Autorisation** : obtenir une autorisation écrite avant tout test, éviter toute activité hors périmètre.

## 3. Environnement de test

- Utiliser un environnement isolé (ex. : environnements Docker dédiés, non impactant la production).
- S’assurer que les données sensibles ne soient pas présentes dans cet environnement.
- Vérifier que les services (Redis, Postgres, Minio, ZAP) soient configurés avec des identifiants sécurisés.

## 4. Outils recommandés

- **OWASP ZAP** : scanner de vulnérabilités pour applications web.
- **Nmap** : scan réseau et détection de services.
- **Wireshark/tcpdump** : analyse réseau.
- **Postman** ou Curl : tests manuels d’API.
- **SQLMAP** : détection et exploitation d'injections SQL.
- **Hydra** : attaque par force brute sur authentification

## 5. Méthodologie

- **Reconnaissance passive** : collecte d’informations sans interaction directe.
- **Reconnaissance active** : scans réseau, port scans, tests de vulnérabilités.
- **Tests d’authentification et d’autorisation** : vérifier que seuls les utilisateurs légitimes accèdent aux ressources.
- **Tests d’injection** : SQL, commandes OS, scripts.
- **Tests spécifiques aux composants** : ex. injection dans Redis, configuration Minio, attaques sur la queue Celery, etc.
- **Analyse des rapports ZAP** : automatiser la récupération et interprétation des résultats.

## 6. Exécution des tests

- Prévenir les équipes concernées avant les tests.
- Eviter les actions destructives ou intrusives non nécessaires.
- Documenter toutes les étapes et résultats.
- Faire attention aux risques de déni de service sur les bases de données et services.

## 7. Reporting

- Lister clairement chaque vulnérabilité avec preuve (captures, logs, requêtes).
- Classer selon la gravité (critique, haute, moyenne, faible).
- Proposer des pistes de remédiation claires.
- S’assurer que le rapport est partagé uniquement avec les parties autorisées.

## 8. Confidentialité et sécurité

- Ne jamais divulguer d’informations sensibles.
- Protéger les données des tests (logs, captures, rapports).
- Supprimer les traces post-tests si besoin.

## 9. Suivi et remédiation

- S’assurer de la correction des vulnérabilités.
- Planifier des tests réguliers, notamment après des mises à jour.
- Mettre à jour ce manuel selon les évolutions du projet.

---

## Annexes

### Liste des ports et services du projet

| Service | Port | Protocole |
|---------|------|-----------|
| Flask (toolbox) | 5000 | HTTP |
| Redis | 6379 | TCP |
| PostgreSQL | 5432 | TCP |
| Minio | 9000 | HTTP |
| Minio Console | 9001 | HTTP |
| ZAP Proxy | 8080 | HTTP |

### Ressources utiles

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [ZAP Documentation](https://www.zaproxy.org/docs/)
- [PostgreSQL Security Best Practices](https://www.postgresql.org/docs/current/security.html)

---

*Ce manuel est un guide évolutif à adapter selon le contexte.*

