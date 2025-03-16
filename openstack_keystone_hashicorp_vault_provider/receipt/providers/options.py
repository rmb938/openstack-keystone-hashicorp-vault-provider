from oslo_config import cfg

hashicorp_vault_opts = [
    cfg.StrOpt(
        "vault_address",
        default="https://127.0.0.1:8200",
        help="Hashicorp Vault Address",
    ),
    cfg.StrOpt(
        "transit_mount_point",
        default="transit",
        help="The mount point to the transit backend",
    ),
    cfg.StrOpt(
        "transit_key_name",
        default="key",
        help="The name of the key to use in the transit backend",
    ),
]
