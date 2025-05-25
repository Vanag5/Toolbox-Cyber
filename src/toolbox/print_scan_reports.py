import json
import argparse
from toolbox.models import scan_reports, ScanResult
from toolbox import db

def load_scan_reports_from_db():
    reports = {}
    for scan in ScanResult.query.all():
        reports[scan.scan_id] = {
            "scan_type": scan.scan_type,
            "target": scan.target,
            "timestamp": scan.timestamp.isoformat(),
            "results": json.loads(scan.results_json),
            "summary": json.loads(scan.summary_json) if scan.summary_json else {}
        }
    return reports

def print_scan_reports(scan_reports, output_file=None, scan_id=None):
    """
    Print or save scan reports.
    Args:
        scan_reports (dict): Dictionary of scan reports.
        output_file (str): File path to save the output (optional).
        scan_id (str): Specific scan ID to filter (optional).
    """
    if not scan_reports:
        print("No scan reports available.")
        return
    filtered_reports = (
        {scan_id: scan_reports[scan_id]
         } if scan_id and scan_id in scan_reports else scan_reports
    )
    output = []
    for scan_id, report in filtered_reports.items():
        output.append(f"\nScan ID: {scan_id}")
        output.append(json.dumps(report, indent=2))
    output_str = "\n".join(output)
    if output_file:
        with open(output_file, "w") as f:
            f.write(output_str)
        print(f"Scan reports saved to {output_file}")
    else:
        print("Scan Reports:")
        print(output_str)
if __name__ == "__main__":
    # ... argparse ...
    parser = argparse.ArgumentParser(description="Print or save scan reports.")
    parser.add_argument("--output", "-o", type=str, help="File path to save the scan reports (optional).")
    parser.add_argument("--scan-id", "-s", type=str, help="Specific scan ID to filter (optional).")
    args = parser.parse_args()

    from toolbox import create_app
    app = create_app()
    with app.app_context():
        scan_reports = load_scan_reports_from_db()
        print_scan_reports(scan_reports, output_file=args.output, scan_id=args.scan_id)