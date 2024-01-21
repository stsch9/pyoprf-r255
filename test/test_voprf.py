from src.oprf_ristretto25519_sha512 import VOPRF, BaseOPRF
from src.utils import modeVOPRF
from pysodium import crypto_scalarmult_ristretto255_base
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
sksm = 'e6f73f344b79b379f1a0dd37e07ff62e38d9f71345ce62ae3a9bc60b04ccd909'
pkSm = 'c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e'


class TestVOPRF(unittest.TestCase):
    def test_derive_key_pair(self):
        base_oprf = BaseOPRF(modeVOPRF)
        skS = base_oprf.DeriveKeyPair(bytes.fromhex(Seed), bytes.fromhex(KeyInfo))[0]
        self.assertEqual(skS, bytes.fromhex(sksm))
        self.assertEqual(crypto_scalarmult_ristretto255_base(skS), bytes.fromhex(pkSm))

    def test_voprf_1(self):
        # test vectors
        Input = '00'
        r = '64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706'
        BlindedElement = '863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945'
        EvaluationElement = 'aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e'
        Proof = 'ddef93772692e535d1a53903db24367355cc2cc78de93b3be5a8ffcc6985dd066d4346421d17bf5117a2a1ff0fcb2a759f58a539dfbe857a40bce4cf49ec600d'
        ProofRandomScalar = '222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e'
        Output = 'b58cfbe118e0cb94d79b5fd6a6dafb98764dff49c14e1770b566e42402da1a7da4d8527693914139caee5bd03903af43a491351d23b430948dd50cde10d32b3c'

        # Blind
        oprf_client = VOPRF(bytes.fromhex(pkSm))
        blinded_element = oprf_client.Blind(bytes.fromhex(Input))
        self.assertEqual(blinded_element, bytes.fromhex(BlindedElement))

        # BlindEvaluate
        oprf_server = VOPRF(bytes.fromhex(pkSm))
        evaluated_element, proof = oprf_server.BlindEvaluate(bytes.fromhex(sksm), bytes.fromhex(BlindedElement))
        self.assertEqual(evaluated_element, bytes.fromhex(EvaluationElement))
        self.assertEqual(proof[0] + proof[1], bytes.fromhex(Proof))

        # Finalize
        output = oprf_client.Finalize(bytes.fromhex(EvaluationElement), proof)
        self.assertEqual(output, bytes.fromhex(Output))

    def test_voprf_2(self):
        # test vectors
        Input = '5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a'
        r = '64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706'
        BlindedElement = 'cc0b2a350101881d8a4cba4c80241d74fb7dcbfde4a61fde2f91443c2bf9ef0c'
        EvaluationElement = '60a59a57208d48aca71e9e850d22674b611f752bed48b36f7a91b372bd7ad468'
        Proof = '401a0da6264f8cf45bb2f5264bc31e109155600babb3cd4e5af7d181a2c9dc0a67154fabf031fd936051dec80b0b6ae29c9503493dde7393b722eafdf5a50b02'
        ProofRandomScalar = '222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e'
        Output = '8a9a2f3c7f085b65933594309041fc1898d42d0858e59f90814ae90571a6df60356f4610bf816f27afdd84f47719e480906d27ecd994985890e5f539e7ea74b6'

        # Blind
        oprf_client = VOPRF(bytes.fromhex(pkSm))
        blinded_element = oprf_client.Blind(bytes.fromhex(Input))
        self.assertEqual(blinded_element, bytes.fromhex(BlindedElement))

        # BlindEvaluate
        oprf_server = VOPRF(bytes.fromhex(pkSm))
        evaluated_element, proof = oprf_server.BlindEvaluate(bytes.fromhex(sksm), bytes.fromhex(BlindedElement))
        self.assertEqual(evaluated_element, bytes.fromhex(EvaluationElement))
        self.assertEqual(proof[0] + proof[1], bytes.fromhex(Proof))

        # Finalize
        output = oprf_client.Finalize(bytes.fromhex(EvaluationElement), proof)
        self.assertEqual(output, bytes.fromhex(Output))


if __name__ == '__main__':
    unittest.main()
