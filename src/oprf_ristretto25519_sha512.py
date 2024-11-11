# https://datatracker.ietf.org/doc/html/rfc9497
# https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16
# https://github.com/algorand/bls_sigs_ref/blob/master/sage-impl/hash_to_field.py
import hashlib
from hmac import compare_digest
from pysodium import (crypto_core_ristretto255_scalar_random, crypto_core_ristretto255_from_hash,
                      crypto_scalarmult_ristretto255, crypto_core_ristretto255_scalar_reduce,
                      crypto_core_ristretto255_scalar_invert, crypto_core_ristretto255_scalar_mul,
                      crypto_core_ristretto255_scalar_sub, crypto_scalarmult_ristretto255_base,
                      crypto_core_ristretto255_add, crypto_core_ristretto255_scalar_add)
from src.utils import (modeOPRF, modeVOPRF, modePOPRF, CreateContextString, identifier, identity, generator, I2OSP,
                       expand_message_xmd)


class BaseOPRF(object):
    def __init__(self, mode):
        self.mode = mode
        self.contextString = CreateContextString(mode, identifier)

    def HashToScalar(self, input: bytes, dst_prefix=b"HashToScalar-") -> bytes:
        DST = dst_prefix + self.contextString
        return crypto_core_ristretto255_scalar_reduce(expand_message_xmd(input, DST, 64, hashlib.sha512))

    # https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf#section-3.2.1
    def DeriveKeyPair(self, seed: bytes, info: bytes) -> tuple[bytes, bytes]:
        deriveInput = seed + I2OSP(len(info), 2) + info
        counter = 0
        skS = (b'\x00' * 32)
        while skS == (b'\x00' * 32):
            if counter > 255:
                raise Exception("Derive Key Pair Error")
            skS = self.HashToScalar(deriveInput + I2OSP(counter, 1), b"DeriveKeyPair")
            counter = counter + 1
        pkS = crypto_scalarmult_ristretto255_base(skS)
        return skS, pkS

    def ComputeCompositesFast(self, k: bytes, B: bytes, C: list, D: list) -> tuple[bytes, bytes]:
        Bm = B
        seedDST = b"Seed-" + self.contextString
        seedTranscript = \
            I2OSP(len(Bm), 2) + Bm + \
            I2OSP(len(seedDST), 2) + seedDST
        seed = hashlib.sha512(seedTranscript).digest()

        M = bytes.fromhex(identity)
        m = len(C)
        for i in range(m):
            Ci = C[i]
            Di = D[i]
            compositeTranscript = \
                I2OSP(len(seed), 2) + seed + I2OSP(i, 2) + \
                I2OSP(len(Ci), 2) + Ci + \
                I2OSP(len(Di), 2) + Di + \
                b"Composite"

            di = self.HashToScalar(compositeTranscript)
            M = crypto_core_ristretto255_add(crypto_scalarmult_ristretto255(di, C[i]), M)

        Z = crypto_scalarmult_ristretto255(k, M)
        return M, Z

    def ComputeComposites(self, B: bytes, C: list, D: list) -> tuple[bytes, bytes]:
        Bm = B
        seedDST = b"Seed-" + self.contextString
        seedTranscript = \
            I2OSP(len(Bm), 2) + Bm + \
            I2OSP(len(seedDST), 2) + seedDST
        seed = hashlib.sha512(seedTranscript).digest()

        M = bytes.fromhex(identity)
        Z = bytes.fromhex(identity)
        m = len(C)
        for i in range(m):
            Ci = C[i]
            Di = D[i]
            compositeTranscript = \
                I2OSP(len(seed), 2) + seed + I2OSP(i, 2) + \
                I2OSP(len(Ci), 2) + Ci + \
                I2OSP(len(Di), 2) + Di + \
                b"Composite"

            di = self.HashToScalar(compositeTranscript)
            M = crypto_core_ristretto255_add(crypto_scalarmult_ristretto255(di, C[i]), M)
            Z = crypto_core_ristretto255_add(crypto_scalarmult_ristretto255(di, D[i]), Z)

        return M, Z

    def GenerateProof(self, k: bytes, A: bytes, B: bytes, C: list, D: list) -> list:
        M, Z = self.ComputeCompositesFast(k, B, C, D)

        r = crypto_core_ristretto255_scalar_random()
        #r = bytes.fromhex('222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e')
        t2 = crypto_scalarmult_ristretto255(r, A)
        t3 = crypto_scalarmult_ristretto255(r, M)

        Bm = B
        a0 = M
        a1 = Z
        a2 = t2
        a3 = t3

        challengeTranscript = \
            I2OSP(len(Bm), 2) + Bm + \
            I2OSP(len(a0), 2) + a0 + \
            I2OSP(len(a1), 2) + a1 + \
            I2OSP(len(a2), 2) + a2 + \
            I2OSP(len(a3), 2) + a3 + \
            b"Challenge"

        c = self.HashToScalar(challengeTranscript)
        s = crypto_core_ristretto255_scalar_sub(r, crypto_core_ristretto255_scalar_mul(c, k))

        return [c, s]

    def VerifyProof(self, A: bytes, B: bytes, C: list, D: list, proof: list) -> bool:
        M, Z = self.ComputeComposites(B, C, D)
        c = proof[0]
        s = proof[1]

        t2 = crypto_core_ristretto255_add(crypto_scalarmult_ristretto255(s, A), crypto_scalarmult_ristretto255(c, B))
        t3 = crypto_core_ristretto255_add(crypto_scalarmult_ristretto255(s, M), crypto_scalarmult_ristretto255(c, Z))

        Bm = B
        a0 = M
        a1 = Z
        a2 = t2
        a3 = t3

        challengeTranscript = \
            I2OSP(len(Bm), 2) + Bm + \
            I2OSP(len(a0), 2) + a0 + \
            I2OSP(len(a1), 2) + a1 + \
            I2OSP(len(a2), 2) + a2 + \
            I2OSP(len(a3), 2) + a3 + \
            b"Challenge"

        expectedC = self.HashToScalar(challengeTranscript)
        return compare_digest(expectedC, c)


class OPRF(BaseOPRF):
    def __init__(self, input: bytes):
        super().__init__(modeOPRF)
        self._input = input
        self.blind = b''

    def Blind(self) -> bytes:
        self.blind = crypto_core_ristretto255_scalar_random()
        #self.blind = bytes.fromhex('64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706')
        DST = b'HashToGroup-' + self.contextString
        inputElement = crypto_core_ristretto255_from_hash(expand_message_xmd(self._input, DST, 64, hashlib.sha512))
        if inputElement == bytes.fromhex(identity):
            raise ValueError('Invalid Input')
        blindedElement = crypto_scalarmult_ristretto255(self.blind, inputElement)
        return blindedElement

    @staticmethod
    def BlindEvaluate(skS: bytes, blindedElement: bytes) -> bytes:
        evaluatedElement = crypto_scalarmult_ristretto255(skS, blindedElement)
        return evaluatedElement

    def Finalize(self, evaluatedElement: bytes) -> bytes:
        unblindedElement = crypto_scalarmult_ristretto255(crypto_core_ristretto255_scalar_invert(self.blind),
                                                          evaluatedElement)
        hashInput = I2OSP(len(self._input), 2) + self._input + I2OSP(len(unblindedElement), 2) + unblindedElement + b'Finalize'
        return hashlib.sha512(hashInput).digest()


class VOPRF(BaseOPRF):
    def __init__(self, pkS: bytes):
        super().__init__(modeVOPRF)
        self.pkS = pkS
        self._input = b''
        self.blind = b''
        self.blindedElement = b''

    def Blind(self, input: bytes) -> bytes:
        self._input = input
        self.blind = crypto_core_ristretto255_scalar_random()
        #self.blind = bytes.fromhex('64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706')
        DST = b'HashToGroup-' + self.contextString
        inputElement = crypto_core_ristretto255_from_hash(expand_message_xmd(self._input, DST, 64, hashlib.sha512))
        if inputElement == bytes.fromhex(identity):
            raise ValueError('Invalid Input')
        self.blindedElement = crypto_scalarmult_ristretto255(self.blind, inputElement)
        return self.blindedElement

    def BlindEvaluate(self, skS: bytes, blindedElement: bytes) -> tuple[bytes, list]:
        evaluatedElement = crypto_scalarmult_ristretto255(skS, blindedElement)
        blindedElements = [blindedElement]
        evaluatedElements = [evaluatedElement]
        proof = self.GenerateProof(skS, bytes.fromhex(generator), self.pkS, blindedElements, evaluatedElements)
        return evaluatedElement, proof

    def Finalize(self, evaluatedElement: bytes, proof: list) -> bytes:
        blindedElements = [self.blindedElement]
        evaluatedElements = [evaluatedElement]
        if not self.VerifyProof(bytes.fromhex(generator), self.pkS, blindedElements, evaluatedElements, proof):
            raise Exception("Verify Error")

        unblindedElement = crypto_scalarmult_ristretto255(crypto_core_ristretto255_scalar_invert(self.blind),
                                                          evaluatedElement)

        hashInput = \
            I2OSP(len(self._input), 2) + self._input + \
            I2OSP(len(unblindedElement), 2) + unblindedElement + \
            b"Finalize"

        return hashlib.sha512(hashInput).digest()


class POPRF(BaseOPRF):
    def __init__(self, info: bytes):
        super().__init__(modePOPRF)
        self.info = info
        self._input = b''
        self.blind = b''
        self.tweakedKey = b''
        self.blindedElement = b''

    def Blind(self, input: bytes, pkS: bytes) -> bytes:
        self._input = input
        framedInfo = b"Info" + I2OSP(len(self.info), 2) + self.info
        m = self.HashToScalar(framedInfo)
        T = crypto_scalarmult_ristretto255_base(m)
        self.tweakedKey = crypto_core_ristretto255_add(T, pkS)
        if self.tweakedKey == bytes.fromhex(identity):
            raise ValueError('Invalid Input')

        self.blind = crypto_core_ristretto255_scalar_random()
        #self.blind = bytes.fromhex('64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706')
        DST = b'HashToGroup-' + self.contextString
        inputElement = crypto_core_ristretto255_from_hash(expand_message_xmd(self._input, DST, 64, hashlib.sha512))
        if inputElement == bytes.fromhex(identity):
            raise ValueError('Invalid Input')

        self.blindedElement = crypto_scalarmult_ristretto255(self.blind, inputElement)
        return self.blindedElement

    def BlindEvaluate(self, skS: bytes, blindedElement: bytes) -> tuple[bytes, list]:
        framedInfo = b"Info" + I2OSP(len(self.info), 2) + self.info
        m = self.HashToScalar(framedInfo)
        t = crypto_core_ristretto255_scalar_add(skS, m)
        if t ==  32 * b'\x00':
            raise Exception("Inverse Error")

        evaluatedElement = crypto_scalarmult_ristretto255(t, blindedElement)

        tweakedKey = crypto_scalarmult_ristretto255_base(t)
        blindedElements = [blindedElement]
        evaluatedElements = [evaluatedElement]
        proof = self.GenerateProof(t, bytes.fromhex(generator), tweakedKey, blindedElements, evaluatedElements)

        return evaluatedElement, proof

    def Finalize(self, evaluatedElement: bytes, proof: list) -> bytes:
        blindedElements = [self.blindedElement]
        evaluatedElements = [evaluatedElement]
        if not self.VerifyProof(bytes.fromhex(generator), self.tweakedKey, blindedElements, evaluatedElements, proof):
            raise Exception("Verify Error")

        unblindedElement = crypto_scalarmult_ristretto255(crypto_core_ristretto255_scalar_invert(self.blind),
                                                          evaluatedElement)

        hashInput = \
            I2OSP(len(self._input), 2) + self._input + \
            I2OSP(len(self.info), 2) + self.info + \
            I2OSP(len(unblindedElement), 2) + unblindedElement + \
            b"Finalize"

        return hashlib.sha512(hashInput).digest()