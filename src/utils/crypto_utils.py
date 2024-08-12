import hashlib

def sha256_hash(data):
    """
    Verilen veriyi SHA-256 hash fonksiyonuyla hashler.
    
    :param data: Hashlenecek veri (bytes olarak)
    :return: Hashlenmiş veri (bytes olarak)
    """
    return hashlib.sha256(data).digest()
