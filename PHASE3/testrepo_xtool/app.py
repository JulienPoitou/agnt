import yaml


def charge_config(chemin):
    with open(chemin) as f:
        # yaml.load sans Loader sûr : désérialisation arbitraire possible.
        # Détecté par Semgrep (avoid-pyyaml-load) alors que le paquet pyyaml==5.1
        # est lui-même vulnérable — détecté par Trivy. C'est le lien inter-outils.
        return yaml.load(f, Loader=yaml.Loader)
