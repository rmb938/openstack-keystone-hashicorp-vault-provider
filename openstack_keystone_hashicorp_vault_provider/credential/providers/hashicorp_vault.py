import base64

import hvac
from keystone.credential.providers import core
from keystone.i18n import _
from oslo_config import cfg

from openstack_keystone_hashicorp_vault_provider.credential.providers.options import (
    hashicorp_vault_opts,
)

CONF = cfg.CONF
CONF.register_opts(hashicorp_vault_opts, group="credential_hashicorp_vault")


def create_vault_client() -> hvac.Client:
    client = hvac.Client(
        url=CONF.credential_hashicorp_vault.vault_address,
    )
    client.is_authenticated()

    return client


class Provider(core.Provider):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        create_vault_client()

    def encrypt(self, credential):
        client = create_vault_client()

        encrypt_resp = client.secrets.transit.encrypt_data(
            mount_point=CONF.credential_hashicorp_vault.transit_mount_point,
            name=CONF.credential_hashicorp_vault.transit_key_name,
            plaintext=base64.standard_b64encode(credential).decode("utf-8"),
        )

        return encrypt_resp["data"]["ciphertext"]

    def decrypt(self, credential):
        client = create_vault_client()

        decrypt_resp = client.secrets.transit.decrypt_data(
            mount_point=CONF.credential_hashicorp_vault.transit_mount_point,
            name=CONF.credential_hashicorp_vault.transit_key_name,
            ciphertext=credential,
        )

        return decrypt_resp["data"]["plaintext"]
