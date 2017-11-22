from cpabe import *
import hashlib

class kem(object):
    def __init__(self, policy, group = False, key = False, verify = False):
        """
        key must be {'msk':xxxx, 'pk':xxxx} or False
        """
        self.pol = policy

        if group is False:
            self.groupObj = PairingGroup('SS512')
        else:
            self.groupObj = group
        
        self.cpabe = CPabe_zjz(self.groupObj)
        
        if key is False:
            self.key = {}
            self.key['msk'], self.key['pk'] = self.cpabe.setup()
        else:
            self.key = key

        self.verify = verify

    def gen_key(self, sym_key = False):
        """
        key must be string or False(random generate)
        """
        if sym_key is False:
            sym_key = self.groupObj.random(ZR)
        else:
            sym_key = self.groupObj.hash(sym_key, ZR)
        
        # convert sym_key from ZR to GT (can not directly hash string to GT)
        sym_key1 = self.groupObj.hash(sym_key, G1)
        sym_key2 = self.groupObj.hash(sym_key, G1)
        sym_key = self.groupObj.pair_prod(sym_key1, sym_key2)

        m_verify = self.groupObj.random(GT)
        self.CT = self.cpabe.encrypt(self.key['pk'], sym_key, m_verify, self.pol)

        self.sym_key = hashlib.sha256(self.groupObj.serialize(sym_key)).hexdigest()

        return self.sym_key, self.CT, self.key

    def cpabe_key(self, attr, key):
        skx = self.cpabe.keygen(key['pk'], key['msk'], attr)
        return skx

    def get_key(self, ct, key, skx):
        self.key = key
        M = self.cpabe.decrypt(key['pk'], skx, ct)
        sym_key = hashlib.sha256(self.groupObj.serialize(M)).hexdigest()
        
        return sym_key
    
def main():
    #Get the eliptic curve with the bilinear mapping feature needed.
    pol = '((ONE or THREE) and (TWO or FOUR) or (FIVE and SIX and SEVEN and EIGHT or NINE or TEN and ELEVEN or TWELL))'

    kemObj = kem(pol)
    sym_key, ct, key = kemObj.gen_key('password')
    print(sym_key)
    print(ct)
    attr_list = ['THREE', 'ONE', 'TWO']
    skx = kemObj.cpabe_key(attr_list, key)
    sym_key = kemObj.get_key(ct, key, skx)
    print(sym_key)
    

if __name__ == '__main__':
    debug = True
    main()