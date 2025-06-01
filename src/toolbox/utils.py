def parse_sqlmap_output(raw_output: str):
    results = []
    dbms = None
    current_vuln = {}

    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Détection du DBMS
        if "the back-end DBMS is" in line:
            dbms = line.split("is")[-1].strip()

        # Ligne de vulnérabilité en un seul bloc
        if line.lower().startswith("parameter:"):
            # Exemple : Parameter: artist, payload: '1 AND 1=1', dbms: MySQL
            if current_vuln:
                results.append(current_vuln)
            current_vuln = {}
            parts = [p.strip() for p in line.split(",")]
            for part in parts:
                if ':' in part:
                    key, val = part.split(":", 1)
                    key = key.lower().strip()
                    val = val.strip()
                    if key == 'parameter':
                        current_vuln['parameter'] = val
                    elif key == 'payload':
                        current_vuln['payload'] = val
                    elif key == 'dbms':
                        current_vuln['dbms'] = val

        elif line.lower().startswith("type:") or line.lower().startswith("title:"):
            current_vuln["vulnerability"] = line.split(":", 1)[-1].strip()

    if current_vuln:
        results.append(current_vuln)

    # Ajout du DBMS s'il n'est pas présent dans certaines entrées
    for r in results:
        if 'dbms' not in r and dbms:
            r['dbms'] = dbms

    return results, dbms
