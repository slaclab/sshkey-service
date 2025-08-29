import base64

from fastapi import HTTPException
from loguru import logger
import paramiko
import pendulum

class KeyBundle:
    def __init__(
        self,
        username: str,
        public_key_str: str,
        source_ip: str,
        valid_seconds: int = 90000,
        expires_seconds: int = 604800
    ):
        self.username = username
        self.source_ip = source_ip
        self.finger_print, self.pkey = self._determine_public_key(public_key_str),
        self.public = self.pkey.get_base64(),
        self.key_type = self.pkey.get_name(),
        self.key_bits = self.pkey.get_bits(),
        self.created_at = pendulum.now(),
        self.valid_until = self.created_at.add(seconds=valid_seconds),
        self.expires_at = self.created_at.add(seconds=expires_seconds)

    def _determine_public_key(key: str) -> str:
        """
        Strips the public key of any comments or other unnecessary parts.
        Returns the cleaned public key and its fingerprint.
        """
        found = None

        # ---- BEGIN SSH2 PUBLIC KEY ----
        # Comment: "256-bit ED25519, converted by ytl@yees-m3-mac.lan from OpenS"
        # AAAAC3NzaC1lZDI1NTE5AAAAIGs4y2orDiyCSpY/12Psser9E+q9GzF7133Wu4wBtCqE
        #---- END SSH2 PUBLIC KEY ----
        in_key_block = False
        key_data_base64 = ""
        key_type = None
        for line in public_key.public_key.splitlines():
            if line.strip() == "---- BEGIN SSH2 PUBLIC KEY ----":
                in_key_block = True
                continue
            elif line.strip() == "---- END SSH2 PUBLIC KEY ----":
                break

            if in_key_block:
                if line.strip().startswith("Comment:"):
                    # Extract key type from comment
                    comment = line.strip().split(':', 1)[1].strip()
                    if "ED25519" in comment:
                        key_type = "ssh-ed25519"
                    elif "RSA" in comment:
                        key_type = "ssh-rsa"
                    # Add other key types as needed
                    continue
                else:
                    key_data_base64 += line.strip()

        # error out if not valid
        if not key_data_base64 or not key_type:
            raise HTTPException(status_code=400, detail="Invalid public key format. Please ensure it is in the correct format.")

        found = None
        try:
            found = paramiko.PKey.from_type_string(key_type, base64.b64decode(key_data_base64))
        except Exception as e:
            raise HTTPException(status_code=400, detail="Could not parse the public key. Please ensure it is in the correct format.")

        # remove trailing '=' and replace '/' with '.' since we can't have filenames with '/' in them
        finger_print = found.fingerprint.rstrip('=').replace('/','.').replace('+','.')

        logger.info(f"Found public key {finger_print}: {found}")
        return finger_print, found

    def to_iso(item: dict):
        """Convert pendulum timestamps in the bundle to ISO 8601 strings."""
        bundle = item.copy()
        for k in ('created_at', 'valid_until', 'expires_at'):
            if isinstance(bundle.get(k), pendulum.DateTime):
                bundle[k] = bundle[k].to_iso8601_string()
        return bundle

    def to_pendulum(item: dict):
        """Convert ISO 8601 strings in the bundle to pendulum timestamps."""
        bundle = item.copy()
        for k in ('created_at', 'valid_until', 'expires_at'):
            if bundle.get(k) and not isinstance(bundle[k], pendulum.DateTime):
                bundle[k] = pendulum.parse(bundle[k])
        return bundle

    def build(
            username: str,
            public_key_str: str,
            source_ip: str,
            valid_unt: int = 90000,
            expires_seconds: int = 604800
    ):

            finger_print, pkey = KeyBundle.determine_public_key(public_key_str)
            now = pendulum.now()

            bundle = {
                'username': username,
                'finger_print': finger_print,
                'public_key': pkey.get_base64(),
                'key_type': pkey.get_name(),
                'key_bits': pkey.get_bits(),
                'source_ip': source_ip,
                'created_at': now,
                'valid_until': now.add(seconds=valid_seconds),
                'expires_at': now.add(seconds=expires_seconds)
            }

            return bundle
