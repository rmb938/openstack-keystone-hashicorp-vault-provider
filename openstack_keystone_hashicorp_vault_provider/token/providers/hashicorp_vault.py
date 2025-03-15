# This code is modified from Openstack Keystone source
# keystone/token/providers/jws/core.py
# Modified by Ryan Belgrave on 2025-03-15.
# Modifications include:
# - Changing JWSFormatter to sign using Hashicorp Vault
# - Changing JWSFormatter to get public keys from Hashicorp Vault
# - Adding additional configuration sections

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
import base64
import datetime
import json

import hvac
import jwt
from keystone import exception
from keystone.common import utils
from keystone.i18n import _
from keystone.token.providers import base
from oslo_config import cfg
from oslo_utils import timeutils

from openstack_keystone_hashicorp_vault_provider.token.providers.options import (
    hashicorp_vault_opts,
)

CONF = cfg.CONF
CONF.register_opts(hashicorp_vault_opts, group="token_hashicorp_vault")


def create_vault_client() -> hvac.Client:
    client = hvac.Client(
        url=CONF.token_hashicorp_vault.vault_address,
    )
    client.is_authenticated()

    return client


class Provider(base.Provider):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        create_vault_client()

        self.token_formatter = JWSFormatter()

    def generate_id_and_issued_at(self, token):
        return self.token_formatter.create_token(
            token.user_id,
            token.expires_at,
            token.audit_ids,
            token.methods,
            system=token.system,
            domain_id=token.domain_id,
            project_id=token.project_id,
            trust_id=token.trust_id,
            federated_group_ids=token.federated_groups,
            identity_provider_id=token.identity_provider_id,
            protocol_id=token.protocol_id,
            access_token_id=token.access_token_id,
            app_cred_id=token.application_credential_id,
            thumbprint=token.oauth2_thumbprint,
        )

    def validate_token(self, token_id):
        return self.token_formatter.validate_token(token_id)


class JWSFormatter:

    @property
    def public_keys(self):
        client = create_vault_client()
        token_keys_resp = client.secrets.transit.read_key(
            mount_point="transit_openstack_keystone_token", name="token"
        )

        keys = []

        for version, key_data in token_keys_resp["data"]["keys"].items():
            keys += key_data["public_key"]

        return keys

    def create_token(
        self,
        user_id,
        expires_at,
        audit_ids,
        methods,
        system=None,
        domain_id=None,
        project_id=None,
        trust_id=None,
        federated_group_ids=None,
        identity_provider_id=None,
        protocol_id=None,
        access_token_id=None,
        app_cred_id=None,
        thumbprint=None,
    ):
        issued_at = utils.isotime(subsecond=True)
        issued_at_int = self._convert_time_string_to_int(issued_at)
        expires_at_int = self._convert_time_string_to_int(expires_at)

        payload = {
            # public claims
            "sub": user_id,
            "iat": issued_at_int,
            "exp": expires_at_int,
            # private claims
            "openstack_methods": methods,
            "openstack_audit_ids": audit_ids,
            "openstack_system": system,
            "openstack_domain_id": domain_id,
            "openstack_project_id": project_id,
            "openstack_trust_id": trust_id,
            "openstack_group_ids": federated_group_ids,
            "openstack_idp_id": identity_provider_id,
            "openstack_protocol_id": protocol_id,
            "openstack_access_token_id": access_token_id,
            "openstack_app_cred_id": app_cred_id,
            "openstack_thumbprint": thumbprint,
        }

        # NOTE(lbragstad): Calling .items() on a dictionary in python 2 returns
        # a list but returns an iterable in python 3. Casting to a list makes
        # it safe to modify the dictionary while iterating over it, regardless
        # of the python version.
        for k, v in list(payload.items()):
            if v is None:
                payload.pop(k)

        header = base64.urlsafe_b64encode(
            json.dumps(
                {
                    "alg": "ES256",
                    "typ": "JWT",
                }
            ).encode("utf-8")
        ).decode("utf-8")

        payload = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode(
            "utf-8"
        )

        message = base64.standard_b64encode(
            f"{header}.{payload}".encode("utf-8")
        ).decode("utf-8")

        client = create_vault_client()
        sign_resp = client.secrets.transit.sign_data(
            mount_point="transit_openstack_keystone_token",
            name="token",
            hash_algorithm="sha2-384",
            hash_input=message,
        )

        signature = sign_resp["data"]["signature"].remove_prefix("vault:v1:")

        token_id = f"{header}.{payload}.{signature}"

        # TODO: use vault transit backend to sign jwt
        # See https://github.com/hashicorp/vault/issues/5333#issuecomment-678725132
        # Can't use python jwt cause we don't have the private key
        # Probably could do a custom implementation somehow, but that's a lot of work.

        return token_id, issued_at

    def validate_token(self, token_id):
        payload = self._decode_token_from_id(token_id)

        user_id = payload["sub"]
        expires_at_int = payload["exp"]
        issued_at_int = payload["iat"]
        methods = payload["openstack_methods"]
        audit_ids = payload["openstack_audit_ids"]

        system = payload.get("openstack_system", None)
        domain_id = payload.get("openstack_domain_id", None)
        project_id = payload.get("openstack_project_id", None)
        trust_id = payload.get("openstack_trust_id", None)
        federated_group_ids = payload.get("openstack_group_ids", None)
        identity_provider_id = payload.get("openstack_idp_id", None)
        protocol_id = payload.get("openstack_protocol_id", None)
        access_token_id = payload.get("openstack_access_token_id", None)
        app_cred_id = payload.get("openstack_app_cred_id", None)
        thumbprint = payload.get("openstack_thumbprint", None)

        issued_at = self._convert_time_int_to_string(issued_at_int)
        expires_at = self._convert_time_int_to_string(expires_at_int)

        return (
            user_id,
            methods,
            audit_ids,
            system,
            domain_id,
            project_id,
            trust_id,
            federated_group_ids,
            identity_provider_id,
            protocol_id,
            access_token_id,
            app_cred_id,
            thumbprint,
            issued_at,
            expires_at,
        )

    def _decode_token_from_id(self, token_id):
        options = dict()
        options["verify_exp"] = False
        for public_key in self.public_keys:
            try:
                return jwt.decode(
                    token_id,
                    public_key,
                    algorithms="ES256",
                    options=options,
                )
            except (jwt.InvalidSignatureError, jwt.DecodeError):
                pass  # nosec: We want to exhaustively try all public keys
        raise exception.TokenNotFound(token_id=token_id)

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
        return utils.isotime(at=time_object, subsecond=True)
