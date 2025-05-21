from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp

def test_openvas_connection():
    try:
        # Remplace ici par ton hôte / mot de passe si différent
        connection = TLSConnection(hostname='localhost', port=9390)
        with Gmp(connection) as gmp:
            gmp.authenticate('admin', 'mot_de_passe')  # À adapter
            version = gmp.get_version()
            print(f"✅ Connexion réussie — OpenVAS version : {version}")
    except Exception as e:
        print(f"❌ Erreur lors de la connexion à OpenVAS : {e}")

if __name__ == "__main__":
    test_openvas_connection()
