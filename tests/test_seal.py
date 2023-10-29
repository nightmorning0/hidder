from seal import Sealer
from pathlib import Path
from shutil import rmtree
from os import remove
from cryptography.fernet import Fernet
from pytest import fixture

SRC_DIR = "tests/test_src"
ENC_DIR = "tests/test_enc"
DEC_DIR = "tests/test_dec"
TOKEN_FILE = "token"
BLOCK_SIZE = 512

@fixture
def temp_files():
    token = Fernet.generate_key()
    with open(TOKEN_FILE, "wb") as fp:
        fp.write(token)
    yield
    try:
        remove(TOKEN_FILE)
    except:
        pass
    rmtree(ENC_DIR, ignore_errors=True)
    rmtree(DEC_DIR, ignore_errors=True)

def test_encrypt_and_decrypt(temp_files):
    s = Sealer(SRC_DIR, ENC_DIR, TOKEN_FILE)
    s.encrypt_multiprocesses(2)

    s2 = Sealer(ENC_DIR, DEC_DIR, TOKEN_FILE)
    s2.decrypt_multiprocesses(2)

    for p in Path(SRC_DIR).rglob("[A-Z].*"):
        r_path = p.relative_to(Path(SRC_DIR))
        assert (Path(DEC_DIR)/r_path).exists(), f"{Path(DEC_DIR)/r_path}"
        fp_src = open(p, 'rb')
        fp_dec = open(Path(DEC_DIR)/r_path, 'rb')
        
        src_bytes = fp_src.read()
        dec_bytes = fp_dec.read()
        while len(src_bytes) != 0:
            assert src_bytes == dec_bytes, f"{str(fp_src)}, {str(fp_dec)}"
            src_bytes = fp_src.read()
            dec_bytes = fp_dec.read()
        
        assert len(dec_bytes) == 0, f"{str(fp_src)}, {str(fp_dec)}"

        fp_src.close()
        fp_dec.close()
    

    
    
    
    
    