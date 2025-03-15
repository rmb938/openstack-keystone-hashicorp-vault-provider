from oslo_config import cfg

hashicorp_vault_opts = [
    cfg.StrOpt(
        "vault_address",
        default="https://127.0.0.1:8200",
        help="Hashicorp Vault Address",
    ),
]
