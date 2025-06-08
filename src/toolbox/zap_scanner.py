import time
import json
import traceback
from zapv2 import ZAPv2
from toolbox.logger import logger
from datetime import datetime
from toolbox import db
from .models import ZAPScanResult

class ZAPScanner:
    def __init__(self, app=None):
        self.app = app
        self.zap = ZAPv2(
            apikey='',
            proxies={
                'http': 'http://zap:8080',
                'https': 'http://zap:8080',
            }
        )

    def run_zap_scan(self, url, scan_type='spider', level='Default', context_name='default'):
        try:
            with self.app.app_context():
                self.zap.context.new_context(context_name)
                self.zap.context.include_in_context(context_name, f'{url}.*')

                if scan_type == 'spider':
                    scan = self.zap.spider.scan(url, contextname=context_name)
                    while int(self.zap.spider.status(scan)) < 100:
                        time.sleep(2)
                elif scan_type == 'active':
                    self.zap.ascan.enable_all_scanners()
                    scan = self.zap.ascan.scan(url, contextname=context_name)
                    while int(self.zap.ascan.status(scan)) < 100:
                        time.sleep(2)

                alerts = self.zap.core.alerts(baseurl=url)
                results = [{
                    'alert': alert.get('alert', ''),
                    'risk': alert.get('risk', ''),
                    'description': alert.get('description', ''),
                    'uri': alert.get('uri', ''),
                    'param': alert.get('param', ''),
                    'solution': alert.get('solution', '')
                } for alert in alerts]

                summary = {
                    'total_alerts': len(alerts),
                    'risk_levels': {
                        'High': len([a for a in alerts if a['risk'] == 'High']),
                        'Medium': len([a for a in alerts if a['risk'] == 'Medium']),
                        'Low': len([a for a in alerts if a['risk'] == 'Low']),
                        'Informational': len([a for a in alerts if a['risk'] == 'Informational']),
                    }
                }

#                scan_result = ZAPScanResult(
#                    scan_id=scan_id,
#                    scan_type=f'zap_{scan_type}',
#                    target_url=url,
#                    timestamp=datetime.now(),
#                    results_json=json.dumps(results),
#                    summary_json=json.dumps(summary),
#                    raw_output=json.dumps(alerts),
#                    task_id=None,
#                    task_type='zap'
#                )
#                db.session.add(scan_result)
#                db.session.commit()

                return {
                    'status': 'completed',
                    'results': results,
                    'summary': summary
                }

        except Exception as e:
            logger.log_error(
                error_type='zap_scan_error',
                error_message=str(e),
                stack_trace=traceback.format_exc()
            )
            return {
                'status': 'failed',
                'error': str(e)
            }
