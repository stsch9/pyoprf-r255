from src.oprf_ristretto25519_sha512 import OPRF, BaseOPRF
from src.utils import modeOPRF
from pysodium import crypto_core_ristretto255_from_hash, crypto_scalarmult_ristretto255
import unittest
import hashlib


#def Blind(input: bytes) -> tuple[bytes, bytes]:
#    #blind = crypto_core_ristretto255_scalar_random()
#    DST = b'HashToGroup-' + contextString
#    blind = bytes.fromhex(r)
#    inputElement = crypto_core_ristretto255_from_hash(expand_message_xmd(input, DST, 64, hashlib.sha512))
#    if inputElement == bytes.fromhex(identity):
#        raise ValueError('Invalid Input')
#    blindedElement = crypto_scalarmult_ristretto255(blind, inputElement)
#    return blind, blindedElement

# global test vectors
Seed = 'a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3'
KeyInfo = '74657374206b6579'
sksm = '5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e'


class TestOPRF(unittest.TestCase):
    def test_derive_key_pair(self):
        base_oprf = BaseOPRF(modeOPRF)
        skS = base_oprf.DeriveKeyPair(bytes.fromhex(Seed), bytes.fromhex(KeyInfo))[0]
        self.assertEqual(skS, bytes.fromhex(sksm))

    def test_oprf_1(self):
        # test vectors
        Input = '00'
        r = '64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706'
        BlindedElement = '609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c'
        EvaluationElement = '7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e'
        Output = '527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6'

        # Blind
        oprf = OPRF(bytes.fromhex(Input))
        blinded_element = oprf.Blind()
        self.assertEqual(blinded_element, bytes.fromhex(BlindedElement))

        # BlindEvaluate
        evaluated_element = oprf.BlindEvaluate(bytes.fromhex(sksm), bytes.fromhex(BlindedElement))
        self.assertEqual(evaluated_element, bytes.fromhex(EvaluationElement))

        # Finalize
        output = oprf.Finalize(bytes.fromhex(EvaluationElement))
        self.assertEqual(output, bytes.fromhex(Output))

    def test_oprf_2(self):
        # test vectors
        Input = '5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a'
        r = '64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706'
        BlindedElement = 'da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418'
        EvaluationElement = 'b4cbf5a4f1eeda5a63ce7b77c7d23f461db3fcab0dd28e4e17cecb5c90d02c25'
        Output = 'f4a74c9c592497375e796aa837e907b1a045d34306a749db9f34221f7e750cb4f2a6413a6bf6fa5e19ba6348eb673934a722a7ede2e7621306d18951e7cf2c73'

        # Blind
        oprf = OPRF(bytes.fromhex(Input))
        blinded_element = oprf.Blind()
        self.assertEqual(blinded_element, bytes.fromhex(BlindedElement))

        # BlindEvaluate
        evaluated_element = oprf.BlindEvaluate(bytes.fromhex(sksm), bytes.fromhex(BlindedElement))
        self.assertEqual(evaluated_element, bytes.fromhex(EvaluationElement))

        # Finalize
        output = oprf.Finalize(bytes.fromhex(EvaluationElement))
        self.assertEqual(output, bytes.fromhex(Output))


if __name__ == '__main__':
    unittest.main()
