from cpabe import *
from AES import AESCipher

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
    
    def gen_symmetry_key(self, sym_key = False):
        """
        key must be string or False(random generate)
        """
        if sym_key is False:
            sym_key = self.groupObj.random(ZR)
        else:
            sym_key = self.groupObj.hash(sym_key, ZR)
        
        # convert sym_key from ZR to GT (can not directly hash string to GT)
        sym_key1 = self.groupObj.hash(sym_key, G1)
        sym_key2 = self.groupObj.hash(sym_key, G2)
        sym_key = self.groupObj.pair_prod(sym_key1, sym_key2)

        m_verify = self.groupObj.random(GT)
        self.cpabe.encrypt(self.key['pk'], sym_key, m_verify, self.pol)

        # self.m = groupObj.random(GT)
        # if verify:
        #     self.m_ = groupObj.random(GT)

        # if debug:
        #     print('message:>>', self.m)
        #     if verify:
        #         print('message for verification:>>', self.m_)
        
        # self.cipher = cpabe.encrypt(pk, self.m, self.m_, pol)
        
    def get_kvm_key(self, parameter_list):
        pass
    
def main():
    #Get the eliptic curve with the bilinear mapping feature needed.
    groupObj = PairingGroup('SS512')

    cpabe = CPabe_zjz(groupObj)
    (msk, pk) = cpabe.setup()
    pol = '((ONE or THREE) and (TWO or FOUR) or (FIVE and SIX and SEVEN and EIGHT or NINE or TEN and ELEVEN or TWELL))'
    attr_list = ['THREE', 'ONE', 'TWO']

    if debug:
        print('Acces Policy: %s' % pol)
    if debug:
        print('User credential list: %s' % attr_list)
    m = groupObj.random(GT)
    m_ = groupObj.random(GT)
    
    if debug:
        print('message:>>', m)
        print('message for verification:>>', m_)

    cpkey = cpabe.keygen(pk, msk, attr_list)
    
    if debug:
        print("\nSecret key: %s" % attr_list)
    if debug:
        groupObj.debug(cpkey)
    
    cipher = cpabe.encrypt(pk, m, m_, pol)

    if debug:
        print("\nCiphertext...")
    if debug:
        groupObj.debug(cipher)
    
    orig_m = cpabe.decrypt(pk, cpkey, cipher)
    assert m == orig_m, 'FAILED Decryption!!!'
    
    if debug:
        print('Successful Decryption!')

    tk, rk = cpabe.gen_tk_out(pk, cpkey)
    orig_m = cpabe.outsource(pk, cipher, tk, rk)
    assert m == orig_m, 'FAILED Decryption!!!'

    del groupObj


if __name__ == '__main__':
    debug = True
    main()