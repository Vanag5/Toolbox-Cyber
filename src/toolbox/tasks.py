from toolbox.models import SQLMapScanResult, HydraScanResult, ZAPScanResult
from toolbox.port_scanner import PortScanner
from toolbox import db
from toolbox.celery import celery
from toolbox.logger import logger
import json
from toolbox.utils import parse_sqlmap_output
from toolbox.hydra_scanner import HydraScanner
from toolbox.zap_scanner import ZAPScanner
import traceback
from datetime import datetime
from flask import current_app
from zapv2 import ZAPv2

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

@celery.task(bind=True)
def run_hydra_scan(self, target, service, username=None, password=None, user_list=None, pass_list=None, options=None, form_path=None):
    print(f"Hydra scan starting with user_list={user_list} and pass_list={pass_list}")
    """Celery task to run an Hydra brute force scan"""
    print(">>>> TÂCHE HYDRA LANCÉE <<<<") 
    try:
        scanner = HydraScanner()
        result = scanner.run_hydra_scan(target, service, username, password, user_list, pass_list, options, form_path=form_path)
        # Sauvegarde dans la base de données
        scan_result = HydraScanResult(
            scan_id=result['scan_id'],
            scan_type=f'hydra_{service}',
            target=target,
            timestamp=datetime.now(),
            results_json=json.dumps(result['results']),
            summary_json=json.dumps(result['summary'])
        )
        from toolbox import db  # Import tardif pour éviter les cycles
        db.session.add(scan_result)
        db.session.commit()
        return result
    except Exception as e:
        logger.log_error(
            error_type='hydra_scan_task_error',
            error_message=str(e),
            stack_trace=traceback.format_exc()
        )
        raise

@celery.task(bind=True)
def run_zap_scan(self, scan_id, url, scan_type='spider', level='Default'):
    """
    - scan_id   : identifiant généré côté route
    - url       : URL à scanner
    - scan_type : 'spider' ou 'active'
    - level     : niveau (non utilisé ici)
    """
    try:
        # Récupère l’app Flask si on est dans un contexte HTTP (optionnel)
        from flask import has_app_context, current_app
        app = current_app._get_current_object() if has_app_context() else None

        logger.info(f"[ZAP TASK] Lancement du scan {scan_id} sur {url} (type={scan_type})")

        # Initialisation du scanner (ZAP tourne dans son conteneur Docker)
        scanner = ZAPScanner(app=app)

        # Exécution du scan (ne renvoie plus de scan_id ici)
        result = scanner.run_zap_scan(url, scan_type, level)

        # Si le scan a été complété avec succès, on enregistre en base AVEC LE scan_id fourni
        if result.get('status') == 'completed':
            scan_result = ZAPScanResult(
                scan_id=scan_id,                   # <-- on utilise scan_id ici
                scan_type=f'zap_{scan_type}',
                target_url=url,
                timestamp=datetime.now(),
                results_json=json.dumps(result.get('results', [])),
                summary_json=json.dumps(result.get('summary', {})),
                raw_output=json.dumps(result.get('results', [])),
                task_id=self.request.id,
                task_type='zap_scan'
            )
            db.session.add(scan_result)
            db.session.commit()
            logger.info(f"[ZAP TASK] Scan {scan_id} enregistré en base.")

        # Toujours retourner le même scan_id + l’état et résultats
        return {
            'scan_id': scan_id,
            'status': result.get('status'),
            'results': result.get('results', []),
            'summary': result.get('summary', {})
        }

    except Exception as e:
        # En cas d’erreur, on loggue et on signale FAILURE
        logger.log_error(
            error_type='zap_scan_task_error',
            error_message=str(e),
            stack_trace=traceback.format_exc()
        )
        self.update_state(
            state='FAILURE',
            meta={"exc_type": type(e).__name__, "exc_message": str(e)}
        )
        return {
            "scan_id": scan_id,
            "status": "failed",
            "error": str(e)
        }