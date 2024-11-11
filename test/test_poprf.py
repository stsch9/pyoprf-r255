from src.oprf_ristretto25519_sha512 import POPRF, BaseOPRF
from src.utils import modePOPRF
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
sksm = '145c79c108538421ac164ecbe131942136d5570b16d8bf41a24d4337da981e07'
pkSm = 'c647bef38497bc6ec077c22af65b696efa43bff3b4a1975a3e8e0a1c5a79d631'


class TestPOPRF(unittest.TestCase):
    def test_derive_key_pair(self):
        base_oprf = BaseOPRF(modePOPRF)
        skS = base_oprf.DeriveKeyPair(bytes.fromhex(Seed), bytes.fromhex(KeyInfo))[0]
        self.assertEqual(skS, bytes.fromhex(sksm))
        self.assertEqual(crypto_scalarmult_ristretto255_base(skS), bytes.fromhex(pkSm))

    def test_poprf_1(self):
        # test vectors
        Input = '00'
        Info = '7465737420696e666f'
        r = '64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706'
        BlindedElement = 'c8713aa89241d6989ac142f22dba30596db635c772cbf25021fdd8f3d461f715'
        EvaluationElement = '1a4b860d808ff19624731e67b5eff20ceb2df3c3c03b906f5693e2078450d874'
        Proof = '41ad1a291aa02c80b0915fbfbb0c0afa15a57e2970067a602ddb9e8fd6b7100de32e1ecff943a36f0b10e3dae6bd266cdeb8adf825d86ef27dbc6c0e30c52206'
        ProofRandomScalar = '222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e'
        Output = 'ca688351e88afb1d841fde4401c79efebb2eb75e7998fa9737bd5a82a152406d38bd29f680504e54fd4587eddcf2f37a2617ac2fbd2993f7bdf45442ace7d221'

        # Blind
        oprf_client = POPRF(bytes.fromhex(Info), )
        blinded_element = oprf_client.Blind(bytes.fromhex(Input), bytes.fromhex(pkSm))
        self.assertEqual(blinded_element, bytes.fromhex(BlindedElement))

        # BlindEvaluate
        oprf_server = POPRF(bytes.fromhex(Info))
        evaluated_element, proof = oprf_server.BlindEvaluate(bytes.fromhex(sksm), bytes.fromhex(BlindedElement))
        #self.assertEqual(evaluated_element, bytes.fromhex(EvaluationElement))
        #self.assertEqual(proof[0] + proof[1], bytes.fromhex(Proof))

        ## Finalize
        output = oprf_client.Finalize(evaluated_element, proof)
        self.assertEqual(output, bytes.fromhex(Output))

    def test_poprf_2(self):
        # test vectors
        Input = '5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a'
        Info = '7465737420696e666f'
        r = '64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706'
        BlindedElement = 'f0f0b209dd4d5f1844dac679acc7761b91a2e704879656cb7c201e82a99ab07d'
        EvaluationElement = '8c3c9d064c334c6991e99f286ea2301d1bde170b54003fb9c44c6d7bd6fc1540'
        Proof = '4c39992d55ffba38232cdac88fe583af8a85441fefd7d1d4a8d0394cd1de77018bf135c174f20281b3341ab1f453fe72b0293a7398703384bed822bfdeec8908'
        ProofRandomScalar = '222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e'
        Output = '7c6557b276a137922a0bcfc2aa2b35dd78322bd500235eb6d6b6f91bc5b56a52de2d65612d503236b321f5d0bebcbc52b64b92e426f29c9b8b69f52de98ae507'

        # Blind
        oprf_client = POPRF(bytes.fromhex(Info))
        blinded_element = oprf_client.Blind(bytes.fromhex(Input), bytes.fromhex(pkSm))
        self.assertEqual(blinded_element, bytes.fromhex(BlindedElement))

        # BlindEvaluate
        oprf_server = POPRF(bytes.fromhex(Info))
        evaluated_element, proof = oprf_server.BlindEvaluate(bytes.fromhex(sksm), bytes.fromhex(BlindedElement))
        #self.assertEqual(evaluated_element, bytes.fromhex(EvaluationElement))
        #self.assertEqual(proof[0] + proof[1], bytes.fromhex(Proof))

        # Finalize
        output = oprf_client.Finalize(evaluated_element, proof)
        self.assertEqual(output, bytes.fromhex(Output))


if __name__ == '__main__':
    unittest.main()
