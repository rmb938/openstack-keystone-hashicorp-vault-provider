import base64
import datetime
import json

import hvac
import jwt
from keystone import exception
from keystone.common import utils as ks_utils
from keystone.i18n import _
from keystone.models.receipt_model import ReceiptModel
from keystone.receipt.providers import base
from oslo_config import cfg
from oslo_utils import timeutils

from openstack_keystone_hashicorp_vault_provider.credential.providers.options import (
    hashicorp_vault_opts,
)

CONF = cfg.CONF
CONF.register_opts(hashicorp_vault_opts, group="receipt_hashicorp_vault")


def create_vault_client() -> hvac.Client:
    client = hvac.Client(
        url=CONF.receipt_hashicorp_vault.vault_address,
    )
    client.is_authenticated()

    return client


class Provider(base.Provider):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        create_vault_client()

    @property
    def public_keys(self):
        client = create_vault_client()
        token_keys_resp = client.secrets.transit.read_key(
            mount_point=CONF.receipt_hashicorp_vault.transit_mount_point,
            name=CONF.receipt_hashicorp_vault.transit_key_name,
        )

        keys = []

        for _, key_data in token_keys_resp["data"]["keys"].items():
            keys.append(key_data["public_key"])

        return keys

    def validate_receipt(self, receipt_id: str) -> tuple[str, list[str], str, str]:
        payload = self._decode_receipt_from_id(receipt_id)

        user_id = payload["sub"]
        expires_at_int = payload["exp"]
        issued_at_int = payload["iat"]
        methods = payload["openstack_methods"]

        issued_at = self._convert_time_int_to_string(issued_at_int)
        expires_at = self._convert_time_int_to_string(expires_at_int)

        return (user_id, methods, issued_at, expires_at)

    def generate_id_and_issued_at(self, receipt: ReceiptModel) -> tuple[str, str]:
        user_id = receipt.user_id
        methods = receipt.methods
        expires_at = receipt.expires_at

        issued_at = ks_utils.isotime(subsecond=True)

        issued_at_int = self._convert_time_string_to_int(issued_at)
        expires_at_int = self._convert_time_string_to_int(expires_at)

        payload = {
            # public claims
            "sub": user_id,
            "iat": issued_at_int,
            "exp": expires_at_int,
            # private claims
            "openstack_methods": methods,
        }

        header = (
            base64.urlsafe_b64encode(
                json.dumps(
                    {
                        "alg": "ES256",
                        "typ": "JWT",
                    }
                ).encode("utf-8")
            )
            .rstrip(b"=")
            .decode("utf-8")
        )

        jwt_payload = (
            base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8"))
            .rstrip(b"=")
            .decode("utf-8")
        )

        message = base64.standard_b64encode(
            f"{header}.{jwt_payload}".encode("utf-8")
        ).decode("utf-8")

        client = create_vault_client()
        sign_resp = client.secrets.transit.sign_data(
            mount_point=CONF.receipt_hashicorp_vault.transit_mount_point,
            name=CONF.receipt_hashicorp_vault.transit_key_name,
            hash_algorithm="sha2-256",
            marshaling_algorithm="jws",
            hash_input=message,
        )

        signature = sign_resp["data"]["signature"].removeprefix("vault:v1:")

        receipt_id = f"{header}.{jwt_payload}.{signature}"

        return (receipt_id, issued_at)

    def _decode_receipt_from_id(self, receipt_id):
        options = dict()
        options["verify_exp"] = False
        for public_key in self.public_keys:
            try:
                return jwt.decode(
                    receipt_id,
                    public_key,
                    algorithms="ES256",
                    options=options,
                )
            except (jwt.InvalidSignatureError, jwt.DecodeError):
                pass  # nosec: We want to exhaustively try all public keys
        raise exception.ReceiptNotFound(receipt_id=receipt_id)

    def _convert_time_string_to_int(self, time_str):
        time_object = timeutils.parse_isotime(time_str)
        normalized = timeutils.normalize_time(time_object)
        epoch = datetime.datetime.fromtimestamp(0, datetime.timezone.utc).replace(
            tzinfo=None
        )
        return int((normalized - epoch).total_seconds())

    def _convert_time_int_to_string(self, time_int):
        time_object = datetime.datetime.fromtimestamp(
            time_int, datetime.timezone.utc
        ).replace(tzinfo=None)
        return ks_utils.isotime(at=time_object, subsecond=True)
