from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp

def get_vuln_scanner():
    connection = TLSConnection(hostname='localhost', port=9390)
    return Gmp(connection=connection)
