# /// script
# requires-python = ">=3.10"
# dependencies = ["cryptography"]
# ///
"""End-to-end CTAP1/U2F test of a tpm-fido HID device over /dev/hidraw.

Speaks the raw CTAPHID protocol (INIT + MSG) and the U2F register/authenticate
APDUs directly, so nothing about the result depends on a library's opinion.
Verifies the attestation certificate signature and a real user-presence
signature against the public key the token returned.

Two framing gotchas this had to get right:
  * every packet written to the hidraw node is prefixed with a 0x00 report-id
    byte (the token's parser explicitly skips it), and responses come back
    without it;
  * init frames carry the 0x80 "start" bit, i.e. MSG is sent as 0x83, not 0x03.

Usage: run the token, then `uv run tools/verify_ctap1.py`. Each operation pops
a pinentry dialog that must be confirmed; the client re-sends the same APDU
while the token answers SW_WAIT_FOR_TOUCH (0x6985), which is what keeps the
prompt alive.
"""

import glob
import hashlib
import os
import select
import struct
import sys
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

CID_BROADCAST = 0xFFFFFFFF
CTAPHID_PING, CTAPHID_MSG, CTAPHID_INIT, CTAPHID_ERROR = 0x01, 0x03, 0x86, 0xBF

SW_OK, SW_WAIT_FOR_TOUCH = 0x9000, 0x6985


def find_device():
    for d in sorted(glob.glob("/sys/class/hidraw/hidraw*")):
        try:
            uevent = open(os.path.join(d, "device", "uevent"), "rb").read()
        except OSError:
            continue
        if b"tpm-fido" in uevent:
            return "/dev/" + os.path.basename(d)
    return None


class FidoHid:
    def __init__(self, path):
        self.fd = os.open(path, os.O_RDWR)
        self.cid = CID_BROADCAST
        nonce = os.urandom(8)
        r = self.exchange(CTAPHID_INIT, nonce)
        if r[:8] != nonce:
            raise RuntimeError("INIT nonce mismatch")
        self.cid = struct.unpack(">I", r[8:12])[0]
        self.protocol_version = r[12]
        self.device_version = tuple(r[13:16])
        self.capabilities = r[16]

    def close(self):
        os.close(self.fd)

    def _read_packet(self, timeout=10):
        r, _, _ = select.select([self.fd], [], [], timeout)
        if not r:
            raise TimeoutError("timed out reading HID packet")
        raw = os.read(self.fd, 65)
        # uhid reports carry a leading report-id byte
        return raw[1:] if len(raw) == 65 else raw

    def exchange(self, cmd, payload):
        first = struct.pack(">IBH", self.cid, cmd | 0x80, len(payload)) + payload
        os.write(self.fd, b"\0" + first[:64].ljust(64, b"\0"))
        off, seq = 57, 0
        while off < len(payload):
            chunk = payload[off : off + 59]
            os.write(
                self.fd,
                b"\0" + struct.pack(">IB", self.cid, seq) + chunk.ljust(59, b"\0"),
            )
            off += 59
            seq += 1

        while True:
            pkt = self._read_packet()
            rcid, rcmd, rlen = struct.unpack(">IBH", pkt[:7])
            if rcid != self.cid:
                continue
            if rcmd == CTAPHID_ERROR:
                raise RuntimeError(f"CTAPHID error 0x{pkt[7]:02x}")
            if rcmd != (cmd | 0x80):
                continue
            data = bytearray(pkt[7 : 7 + min(rlen, 57)])
            seq = 0
            while len(data) < rlen:
                pkt = self._read_packet()
                if pkt[4] != seq:
                    raise RuntimeError("bad continuation sequence")
                data += pkt[5 : 5 + min(rlen - len(data), 59)]
                seq += 1
            return bytes(data[:rlen])


def send_apdu(dev, apdu, timeout=90, retry_pause=0.75):
    """Send an APDU, retrying while the token says 'waiting for user presence'."""
    deadline = time.time() + timeout
    attempts = 0
    while time.time() < deadline:
        attempts += 1
        resp = dev.exchange(CTAPHID_MSG, apdu)
        sw = struct.unpack(">H", resp[-2:])[0]
        if sw == SW_OK:
            print(f"   (approved after {attempts} attempt(s))")
            return resp[:-2]
        if sw == SW_WAIT_FOR_TOUCH:
            time.sleep(retry_pause)
            continue
        raise RuntimeError(f"APDU failed, status 0x{sw:04x}")
    raise TimeoutError("token never got user presence confirmation")


def der_len(buf, off):
    n = buf[off + 1]
    if n < 0x80:
        return 2, n
    cnt = n & 0x7F
    ln = int.from_bytes(buf[off + 2 : off + 2 + cnt], "big")
    return 2 + cnt, ln


def main():
    path = find_device()
    if not path:
        sys.exit("no HID device named 'tpm-fido' found under /sys/class/hidraw")
    print(f"device: {path}")

    dev = FidoHid(path)
    print(
        f"CTAPHID init ok  cid=0x{dev.cid:08x}  proto={dev.protocol_version} "
        f"fw={dev.device_version} caps=0x{dev.capabilities:02x}"
    )

    ver = send_apdu(dev, bytes.fromhex("000300000000000000"))
    print(f"U2F version: {ver.decode()}")

    app_param = hashlib.sha256(b"https://tpm-fido.test").digest()
    challenge = os.urandom(32)
    print(
        "registering (a pinentry dialog titled 'TPM-FIDO' should appear -> click Confirm)"
    )

    apdu = b"\x00\x01\x00\x00" + b"\x00\x00\x40" + challenge + app_param + b"\x00\x00"
    reg = send_apdu(dev, apdu)

    if reg[0] != 0x05:
        sys.exit(f"unexpected registration reserved byte 0x{reg[0]:02x}")
    pub_point = reg[1:66]
    kh_len = reg[66]
    key_handle = reg[67 : 67 + kh_len]
    rest = reg[67 + kh_len :]

    n, cert_len = der_len(rest, 0)
    cert_der = rest[: n + cert_len]
    att_sig = rest[n + cert_len :]

    cert = x509.load_der_x509_certificate(cert_der)
    print(f"attestation cert subject: {cert.subject.rfc4514_string()}")
    cert.public_key().verify(
        att_sig,
        b"\x00" + app_param + challenge + key_handle + pub_point,
        ec.ECDSA(hashes.SHA256()),
    )
    print(f"attestation signature: VALID   key_handle={kh_len} bytes")

    chal2 = os.urandom(32)
    print("authenticating (second pinentry dialog -> click Confirm)")
    apdu = (
        b"\x00\x02\x03\x00"
        + struct.pack(">I", 65 + kh_len)[1:]
        + chal2
        + app_param
        + bytes([kh_len])
        + key_handle
        + b"\x00\x00"
    )
    auth = send_apdu(dev, apdu)

    flags, counter, sig = auth[0], struct.unpack(">I", auth[1:5])[0], auth[5:]
    if not flags & 0x01:
        sys.exit("user-presence bit was not set")
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_point)
    pub.verify(
        sig,
        app_param + bytes([flags]) + struct.pack(">I", counter) + chal2,
        ec.ECDSA(hashes.SHA256()),
    )
    print(f"authentication signature: VALID   flags=0x{flags:02x} counter={counter}")
    dev.close()
    print("\nRESULT: PASS - register + assert round trip verified end to end")


if __name__ == "__main__":
    main()
