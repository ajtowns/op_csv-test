#!/usr/bin/env python3
# have to use python3 because otherwise bytes() is freaking weird

# Copyright (c) Anthony Towns <aj@erisian.com.au>
# Reusable under GPL v3

import bitcoin
import bitcoin.rpc
import hashlib

from bitcoin.core import (
        b2x, x, b2lx, lx,
        Hash160,
        str_money_value, COIN,
        COutPoint, CTxIn, CMutableTxIn, CTxOut,
        CTransaction, CMutableTransaction,
)
from bitcoin.core.script import (
        OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF, OP_SHA256, OP_HASH160,
        OP_VERIFY, OP_EQUALVERIFY, OP_EQUAL, OP_BOOLOR,
        OP_NOP2, OP_NOP3, OP_IFDUP, OP_DUP, OP_DROP, OP_2DROP,
        OP_CHECKSIG, OP_CHECKSIGVERIFY,
        OP_SWAP, OP_OVER, OP_CODESEPARATOR, OP_FALSE, OP_TRUE, OP_2,
        CScript,
        SignatureHash, SIGHASH_ALL,
)
LOCKTIME_THRESHOLD = 500000000

OP_CLTV = OP_HODL = OP_NOP2
OP_CSV = OP_NOP3

from bitcoin.wallet import P2SHBitcoinAddress, CBitcoinSecret, CBitcoinAddress

def mkhash(basescript, tx, vin, sigflags, drop_codesep=0):
    if drop_codesep > 0:
        sclst = list(basescript)
        assert basescript == CScript(sclst) # not fancy
        for _ in range(dropcs):
            assert OP_CODESEPARATOR in sclst
            sclst = sclst[sclst.index(OP_CODESEPARATOR)+1:]
        basescript = CScript(sclst)
    return SignatureHash(basescript, tx, vin, sigflags)

def mksig(privkey, txhash, sigflags, N=None):
    if N is None:
        return privkey.sign(txhash) + bytes([sigflags])
    else:
        nhash = int.from_bytes(txhash, byteorder='big')
        pkb = privkey.to_bytes()
        if len(pkb) == 33 and pkb[-1] == 1:
            pkb = pkb[:32]
        assert len(pkb) == 32
        sk = ecdsa.SigningKey.from_string(pkb, curve=ecdsa.SECP256k1)
        sig = sk.privkey.sign(nhash, N)
        if sig.s*2 > ecdsa.SECP256k1.order:
            sig.s = ecdsa.SECP256k1.order - sig.s
        return ecdsa.util.sigencode_der(sig.r, sig.s, None) + bytes([sigflags])

class Script(object):
    @property
    def p2sh_scriptPubKey(self):
        return self.script.to_p2sh_scriptPubKey()

    @property
    def p2sh_addr(self):
        return P2SHBitcoinAddress.from_redeemScript(self.script)

    @property
    def spendbytes(self):
        # redeemscript and one sig
        return len(self.script) + 70 + 2

    def mutate_spend(self, tx, vin):
        pass
    def sign_spend(self, tx, vin):
        pass

    def bump_delay(self, tx, vin, delay):
        assert 0 < delay < 2**16
        if tx.nVersion < 2:
            tx.nVersion = 2
        seq = tx.vin[vin].nSequence
        assert seq == 0xFFFFFFFF or seq & 0x80000000 == 0
        if seq == 0xFFFFFFFF:
            d = 0
        d = seq & 0xFFFF
        if d < delay:
            d = delay
        otx = tx.vin[vin]
        tx.vin[vin] = CTxIn(otx.prevout, otx.scriptSig, d)

    def bump_locktime(self, tx, timeout):
        if tx.nLockTime != 0:
            tx_blk = tx.nLockTime < LOCKTIME_THRESHOLD
            to_blk = timeout < LOCKTIME_THRESHOLD
            if (tx_blk and not to_blk):
                raise Exception("Cannot HODL to block time when transaction is already locked by block height")
            elif (not tx_blk and to_blk):
                raise Exception("Cannot HODL to block height when transaction is already locked by block time")

        if tx.nLockTime < timeout:
            tx.nLockTime = timeout

class HODLScript(Script):
    def __init__(self, privkey, timeout, pubkey=None):
        if pubkey is None:
            pubkey = privkey.pub
        self.privkey = privkey
        self.pubkey = pubkey
        self.timeout = timeout

    @property
    def script(self):
        return CScript([self.timeout, OP_CLTV, OP_DROP,
                        self.pubkey, OP_CHECKSIG])

    def mutate_spend(self, tx, vin):
        self.bump_locktime(tx, self.timeout)

    def sign_spend(self, tx, vin):
        txhash = mkhash(self.script, tx, vin, SIGHASH_ALL)
        sig = mksig(self.privkey, txhash, SIGHASH_ALL)
        assert bitcoin.core.script.IsLowDERSignature(sig)
        return CScript([sig, self.script])

class ReceiptScript(Script):
    def __init__(self, paypubkey, refundpubkey,
            secret, timeout,
            privkey=None, secret_pre=None,
            secret_type='sha'):

        assert secret_type == 'sha'
        assert len(secret) == 32
        assert secret_pre is None or len(secret_pre) == 32

        if secret_pre is not None:
            assert privkey is not None
            assert privkey.pub == paypubkey
            assert hashlib.sha256(secret_pre).digest() == secret
        elif privkey is not None:
            assert privkey.pub == refundpubkey

        self.paypubkey = paypubkey
        self.refundpubkey = refundpubkey
        self.secret = secret
        self.timeout = timeout
        self.privkey = privkey
        self.secret_pre = secret_pre
        self.secret_type = secret_type

    @property
    def script(self):
        return CScript([
            OP_IF, OP_SHA256, self.secret, OP_EQUALVERIFY, self.paypubkey,
            OP_ELSE, self.timeout, OP_CLTV, OP_DROP, self.refundpubkey,
            OP_ENDIF, OP_CHECKSIG])

    def mutate_spend(self, tx, vin):
        if self.secret_pre is None:
            self.bump_locktime(tx, self.timeout)

    def sign_spend(self, tx, vin):
        txhash = mkhash(self.script, tx, vin, SIGHASH_ALL)
        sig = mksig(self.privkey, txhash, SIGHASH_ALL)
        if self.secret_pre is not None:
            return CScript([sig, self.secret_pre, OP_TRUE, self.script])
        else:
            return CScript([sig, OP_FALSE, self.script])

class HTLCScript(Script):
    _h_nil = Hash160(b"")
    _h_1 = Hash160(b"\x01")

    def __init__(self, paypubkey, refundpubkey,
            secret, timeout,
            revoke, revoke_side, delay,
            privkey=None, secret_pre=None, revoke_pre=None,
            secret_type='sha'):

        assert revoke_side in ["pay", "refund"]
        assert secret_type == 'sha'

        assert len(secret) == 20
        assert secret_pre is None or len(secret_pre) == 32

        assert len(revoke) == 20

        if revoke_pre is not None:
            assert len(revoke_pre) == 32
            assert Hash160(revoke_pre) == revoke
            assert secret_pre is None
            assert privkey is not None
            assert privkey.pub == (paypubkey if revoke_side == "pay" 
                                   else refundpubkey)
        elif secret_pre is not None:
            assert privkey is not None
            assert privkey.pub == paypubkey
            assert Hash160(secret_pre) == secret
        elif privkey is not None:
            assert privkey.pub == refundpubkey
            if self._h_nil not in [revoke, secret]:
                self.timeout_pre = OP_FALSE
            elif self._h_1 not in [revoke, secret]:
                self.timeout_pre = OP_TRUE
            else:
                self.timeout_pre = OP_2

        self.paypubkey = paypubkey
        self.refundpubkey = refundpubkey
        self.secret = secret
        self.timeout = timeout
        self.privkey = privkey
        self.secret_pre = secret_pre
        self.secret_type = secret_type
        self.delay = delay
        self.revoke_side = revoke_side
        self.revoke = revoke
        self.revoke_pre = revoke_pre

    @property
    def script(self):
        if self.revoke_side == "pay":
            # ((revoke|secret) & pay) | (csv & cltv & refund)
            return CScript([
                OP_HASH160, OP_DUP, self.secret, OP_EQUAL,
                  OP_SWAP, self.revoke, OP_EQUAL, OP_BOOLOR,
                OP_IF, self.paypubkey,
                OP_ELSE,
                  self.delay, OP_CSV, self.timeout, OP_CLTV, OP_2DROP,
                  self.refundpubkey,
                OP_ENDIF, OP_CHECKSIG])
        else:
            # (csv & secret & pay) | ((revoke | cltv) & refund)
            return CScript([
                OP_HASH160, OP_DUP, self.secret, OP_EQUAL,
                OP_IF, self.delay, OP_CSV, OP_2DROP, self.paypubkey,
                OP_ELSE, self.revoke, OP_EQUAL,
                  OP_NOTIF, self.timeout, OP_CLTV, OP_DROP, OP_ENDIF,
                  self.refundpubkey,
                OP_ENDIF, OP_CHECKSIG])

    def mutate_spend(self, tx, vin):
        if self.revoke_pre is None:
            if self.secret_pre is not None:
                self.bump_locktime(tx, self.timeout)
            if self.revoke_side == "pay":
                if self.secret_pre is None:
                    self.bump_delay(tx, vin, self.delay)
            else:
                if self.secret_pre is not None:
                    self.bump_delay(tx, vin, self.delay)

    def sign_spend(self, tx, vin):
        assert self.privkey is not None

        txhash = mkhash(self.script, tx, vin, SIGHASH_ALL)
        sig = mksig(self.privkey, txhash, SIGHASH_ALL)
        if self.revoke_pre is not None:
            return CScript([sig, self.revoke_pre, self.script])
        elif self.secret_pre is not None:
            return CScript([sig, self.secret_pre, self.script])
        else:
            return CScript([sig, self.timeout_pre, self.script])

class SpendScripts(object):
    def __init__(self, payto_addr):
        self.payto = CBitcoinAddress(payto_addr)
        self.proxy = bitcoin.rpc.Proxy()
        self.prevouts = []

    def add_prevout(self, txid, vout, redeemer):
        outpoint = COutPoint(lx(txid), vout)
        try:
            prevout = self.proxy.gettxout(outpoint)
        except IndexError:
            raise Exception("Outpoint %s not found" % (outpoint,))
        prevtx = prevout['txout']
        if prevtx.scriptPubKey != redeemer.p2sh_scriptPubKey:
            raise Exception("Outpoint %s has incorrect scriptPubKey (%s; expected %s)" % (outpoint, b2x(prevtx.scriptPubKey), b2x(redeemer.p2sh_scriptPubKey)))
        self.prevouts.append((outpoint, prevtx, redeemer))

    def as_tx(self):
        sum_in = sum(prevtx.nValue for _,prevtx,_ in self.prevouts)
        sig_size = sum(redeemer.spendbytes for _,_,redeemer in self.prevouts)
        tx_size = (4                        + # version field
                   2                        + # # of txins
                   len(self.prevouts) * 41  + # txins, excluding sigs
                   sig_size                 + # txins, sigs only
                   1                        + # # of txouts
                   34                       + # txout
                   4                          # nLockTime field
                   )
        feerate = int(self.proxy._call('estimatefee', 1) * COIN) 
        # satoshi's per KB
        if feerate <= 0:
            feerate = 10000
        fees = int(tx_size * feerate / 1000)

        tx = CMutableTransaction(
                [CTxIn(outpoint, nSequence=0)
                    for outpoint,_,_ in self.prevouts],
                [CTxOut(sum_in - fees, self.payto.to_scriptPubKey())],
                0)

        for n,(_,_,redeemer) in enumerate(self.prevouts):
            redeemer.mutate_spend(tx, n)

        unsigned_tx = CTransaction.from_tx(tx)

        for n,(_,_,redeemer) in enumerate(self.prevouts):
            txin = CMutableTxIn.from_txin(tx.vin[n])
            txin.scriptSig = redeemer.sign_spend(unsigned_tx, n)
            tx.vin[n] = CTxIn.from_txin(txin)

        print(b2x(tx.serialize()))

bitcoin.SelectParams('regtest')

# parameters

spend = CBitcoinSecret("cVFfsB2h1KHgPEWtpXrnZ5qjk18xw2o2fuxCTaf7BN2Z5PSvhq4M")
refund = CBitcoinSecret("cRKSxo1yJKP1RwaHULWaumNYiyXiQu2tRGdTmUxzP1s4YeSM4ks1")
sec = b'A pair of boiled eggs for lunch?'
sechash = Hash160(sec)
rev = x('4a120469b397556363c4e47f45d8f81b381f721af89baba372425f820ae7077c')
revhash = Hash160(rev)

# the two scripts: paying me or paying them (or refunding to me)
htlcA = HTLCScript(spend.pub, refund.pub, sechash, 230,
                   revhash, 'pay', 10)
htlcB = HTLCScript(spend.pub, refund.pub, sechash, 230,
                   revhash, 'refund', 10)

# the six ways of resolving the scripts: spending, refunding or revoking,
# for both types of script
htlcAs = HTLCScript(spend.pub, refund.pub, sechash, 230,
                   revhash, 'pay', 10, privkey=spend, secret_pre=sec)
htlcAr = HTLCScript(spend.pub, refund.pub, sechash, 230,
                   revhash, 'pay', 10, privkey=refund)
htlcAv = HTLCScript(spend.pub, refund.pub, sechash, 230,
                   revhash, 'pay', 10, privkey=spend, revoke_pre=rev)
htlcBs = HTLCScript(spend.pub, refund.pub, sechash, 230,
                   revhash, 'refund', 10, privkey=spend, secret_pre=sec)
htlcBr = HTLCScript(spend.pub, refund.pub, sechash, 230,
                   revhash, 'refund', 10, privkey=refund)
htlcBv = HTLCScript(spend.pub, refund.pub, sechash, 230,
                   revhash, 'refund', 10, privkey=refund, revoke_pre=rev)

# check that the scripts didn't change, just because how we spend the does
assert htlcA.script == htlcAs.script
assert htlcA.script == htlcAr.script
assert htlcA.script == htlcAv.script
assert htlcB.script == htlcBs.script
assert htlcB.script == htlcBr.script
assert htlcB.script == htlcBv.script

print("P:", htlcA.p2sh_addr, b2x(htlcA.script))
print("R:", htlcB.p2sh_addr, b2x(htlcB.script))

# when testing, run the script up to here to get the two spend addresses,
# then create three outputs for each of them, and enter the values below

r_txns = [
# OP_CSV (and OP_CLTV on refund)
 (htlcAr, 1,"4438112474f70960999c563c289bacf74aa7806fd66c70afeac41a86fcc430cb"),
 (htlcBs, 1,"636c4e0effeacbb5bdc987737f19fab1bf85582d1e27efea7bf5f449f760f87c"),

# no OP_CSV (OP_CLTV on refund)
 (htlcAs, 0,"1521725c01c57de63e51c482e71c0fe1a5be3f0d5c903ff79418aef282dcf30a"),
 (htlcBr, 1,"3c01f185b5f26691d539e5c061e09c6bb8477905ed014b809b25afaeb7f950c7"),

# no delays
 (htlcAv, 0,"4fec5311713b5fd3b1fe34b5ca935d299ef775c2b06a7439ece5f422ef1b3643"),
 (htlcBv, 0,"b878f90c389a152cd52a58b3e433eb070b7eb4dc6ecc2a01815eb3461c6fecf9"),
]

# what address does the money finally go to?
spend = SpendScripts("mq849rB4FrMomQ1gB3RfyygDeALYzrcytR")
for r, vout, txid in r_txns:
    print(vout, txid)
    spend.add_prevout(txid, vout, r)
spend.as_tx()


