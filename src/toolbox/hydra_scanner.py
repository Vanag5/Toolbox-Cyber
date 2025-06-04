import subprocess
from .logger import logger
import traceback
from datetime import datetime
import json
import os
import shutil

class HydraScanner:
    def __init__(self, app=None):
        self.app = app
        self.binary_path = 'hydra'  # Chemin par défaut après installation
        self.default_wordlist_dir = os.path.join(os.path.dirname(__file__), 'wordlists')        

    def run_hydra_scan(self, target, service, username=None, password=None, user_list=None, pass_list=None, options=None, form_path=None):
        print("[Celery Task] run_hydra_scan() started")
        try:
            if not shutil.which(self.binary_path):
                raise EnvironmentError("Hydra binaire non trouvé dans le PATH")
    
            scan_id = f"hydra_{target}_{int(datetime.now().timestamp())}"
            print(f"Scan ID: {scan_id}") 
            
            user_list = self._get_wordlist_path(user_list, 'users.txt')
            pass_list = self._get_wordlist_path(pass_list, 'passwords.txt')

            if service.startswith('http'):
                target_clean = target  # garder protocole http:// ou https://
            else:
                target_clean = target.replace('http://', '').replace('https://', '')

            if service == 'http-post-form':
                if not form_path:
                    raise ValueError("formPath est requis pour le service http-post-form.")

                cmd = [self.binary_path]

                if username:
                    cmd.extend(['-l', username])
                elif user_list:
                    cmd.extend(['-L', user_list])
                else:
                    default_userlist = os.path.join(self.default_wordlist_dir, 'users.txt')
                    if os.path.exists(default_userlist):
                        cmd.extend(['-L', default_userlist])
                    else:
                        raise ValueError("Aucun nom d'utilisateur fourni et aucune liste par défaut trouvée.")

                if password:
                    cmd.extend(['-p', password])
                elif pass_list:
                    cmd.extend(['-P', pass_list])
                else:
                    default_passlist = os.path.join(self.default_wordlist_dir, 'passwords.txt')
                    if os.path.exists(default_passlist):
                        cmd.extend(['-P', default_passlist])
                    else:
                        raise ValueError("Aucun mot de passe fourni et aucune liste par défaut trouvée.")

                if options:
                    for key, value in options.items():
                        cmd.append(key)
                        if value is not None:
                            cmd.append(str(value))

                target_clean = target.replace('http://', '').replace('https://', '')
                if not form_path.count(':') == 2 or '^USER^' not in form_path or '^PASS^' not in form_path:
                    raise ValueError("Le form_path doit contenir exactement deux ':' et inclure ^USER^ et ^PASS^.")

                cmd.append(target_clean)
                cmd.append("http-post-form")
                cmd.append(form_path)

                print("=== CMD HYDRA (shell=False) ===")
                print(" ".join(cmd))
                print("==============================")

                process = subprocess.run(
                    cmd,
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=300
                )

            else:
                # Construction classique en liste
                cmd = [self.binary_path]

                if user_list:
                    cmd.extend(['-L', user_list])
                elif username:
                    cmd.extend(['-l', username])
                else:
                    default_userlist = os.path.join(self.default_wordlist_dir, 'users.txt')
                    if os.path.exists(default_userlist):
                        cmd.extend(['-L', default_userlist])
                    else:
                        raise ValueError("Aucun nom d'utilisateur fourni et aucune liste par défaut trouvée.")

                if pass_list:
                    cmd.extend(['-P', pass_list])
                elif password:
                    cmd.extend(['-p', password])
                else:
                    default_passlist = os.path.join(self.default_wordlist_dir, 'passwords.txt')
                    if os.path.exists(default_passlist):
                        cmd.extend(['-P', default_passlist])
                    else:
                        raise ValueError("Aucun mot de passe fourni et aucune liste par défaut trouvée.")
        
                if options:
                    for key, value in options.items():
                        cmd.extend([key, str(value)])

                if not service:
                    raise ValueError("Le type de service (ssh, http, etc.) est requis pour lancer Hydra.")

                cmd.extend([target_clean, service])

                print("=== CMD HYDRA (shell=False) ===")
                print(" ".join(cmd))
                print("==============================")

                process = subprocess.run(
                    cmd,
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=300
                )

            output = process.stdout + process.stderr
            results = self.parse_output(output)
    
            summary = {
                'total_attempts': len(results),
                'successful_logins': len([r for r in results if r.get('success')])
            }

            logger.log_scan(
                scan_type=f'hydra_{service}',
                target=target,
                results=results
            )

            return {
                'scan_id': scan_id,
                'target': target,
                'service': service,
                'results': results,
                'summary': summary,
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            logger.log_error(
                error_type='hydra_scan_error',
                error_message=str(e),
                stack_trace=traceback.format_exc()
            )
            raise



    def parse_output(self, output):
        """Parse Hydra output to extract results"""
        results = []
        lines = output.split('\n')
        for line in lines:
            if '[SUCCESS]' in line or 'password:' in line:
                # Exemple de sortie Hydra : "[80][http-post-form] host: 192.168.1.1   login: admin   password: 12345"
                parts = line.split()
                if len(parts) >= 6 and 'host:' in line:
                    host = parts[parts.index('host:') + 1]
                    login = parts[parts.index('login:') + 1]
                    password = parts[parts.index('password:') + 1]
                    results.append({
                        'host': host,
                        'login': login,
                        'password': password,
                        'success': True
                    })
        return results
    
    def _get_wordlist_path(self, provided_path, default_filename):
        if provided_path:
            if os.path.isfile(provided_path):
                return provided_path
            else:
                raise ValueError(f"Le fichier spécifié n'existe pas: {provided_path}")
        else:
            default_path = os.path.join(self.default_wordlist_dir, default_filename)
            if os.path.isfile(default_path):
                return default_path
            else:
                raise ValueError(f"Le fichier par défaut est introuvable: {default_path}")