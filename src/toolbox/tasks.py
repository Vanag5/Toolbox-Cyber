from toolbox.models import SQLMapScanResult
from toolbox.port_scanner import PortScanner
from toolbox import db
from toolbox.celery import celery
from toolbox.logger import logger
import json
from toolbox.utils import parse_sqlmap_output

@celery.task(bind=True)
def run_nmap_scan(self, targets, ports):
    # initialisation
    total_steps = len(ports)  # nombre total d'étapes ou de ports à scanner
    results = []
    
    for i, port in enumerate(ports):
        # exécution d'une étape du scan (remplacer par l'appel réel à nmap)
        # result = nmap_scan(targets, port)
        result = f"Scanned {targets} on port {port}"  # placeholder
        results.append(result)
        progress = int((i + 1) / total_steps * 100)
        self.update_state(
            state='PROGRESS',
            meta={
                'progress': progress,
                'message': 'Scan en cours...'
            }
        )
    # fin du scan
    return {'progress': 100, 'message': 'Scan terminé', 'result': results}

@celery.task(bind=True)
def run_sqlmap_scan(self, url, method='GET', data=None, level=1, risk=1, additional_args="", enable_forms_crawl=False, use_tamper=False):
    try:
        scanner = PortScanner()
        result = scanner.run_sqlmap_scan(
            url=url,
            method=method,
            data=data,
            level=level,
            risk=risk,
            additional_args=additional_args,
            enable_forms_crawl=enable_forms_crawl,
            use_tamper=use_tamper
        )

        raw_output = result.get("output") or ""

        print("=== SQLMap raw output snippet ===")
        print(raw_output[:1000])  # Premier kilo de texte
        print("================================")

        parsed_results, dbms = parse_sqlmap_output(raw_output)

        print(f"DBMS détecté : {dbms}")
        print(f"Vulnérabilités détectées : {len(parsed_results)}")
        for vuln in parsed_results:
            print(vuln)

        for i, res in enumerate(parsed_results):
            if not isinstance(res, dict):
                logger.warning(f"Parsed result at index {i} is not a dict: {res}")

        results_json = json.dumps(parsed_results) if parsed_results else json.dumps([])

        summary_data = {
            "total_vulnerabilities": len(parsed_results),
            "dbms_list": list({
                res.get("dbms", "Unknown")
                for res in parsed_results
                if isinstance(res, dict) and res.get("dbms")
            })
        }
        summary_json = json.dumps(summary_data)

        scan = SQLMapScanResult(
            scan_id=result.get("scan_id"),
            target_url=url,
            method=method,
            output_file=result.get("output_file"),
            raw_output=raw_output,
            results_json=results_json,
            summary_json=summary_json, 
            task_id=self.request.id,
            task_type='sqlmap'
        )
        db.session.add(scan)
        db.session.commit()

        return {
            "scan_id": result.get("scan_id"),
            "status": result.get("status"),
            "output_file": result.get("output_file"),
            "raw_output_excerpt": raw_output[:500]
        }

    except Exception as e:
        logger.error(f"[SQLMAP ERROR] {e}")
        self.update_state(
            state='FAILURE',
            meta={"exc_type": type(e).__name__, "exc_message": str(e)}
        )
        raise
