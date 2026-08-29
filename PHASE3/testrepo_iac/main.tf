# Fixture IaC — mauvaises configurations CONNUES et VOLONTAIRES.
# Sert de cible de test au provider checkov (capacité IAC_SCAN).
# Les identifiants de checks attendus sont dans ATTENDUS.yaml — EXTRAIT par exécution
# réelle, jamais écrit à la main (même règle que le mapping des règles Semgrep).

provider "aws" {
  region = "us-east-1"
}

# Bucket public : ACL publique, pas de chiffrement, pas de versioning, pas de logs.
resource "aws_s3_bucket" "public_assets" {
  bucket = "exemple-public-assets"
  acl    = "public-read"
}

# Volume non chiffré.
resource "aws_ebs_volume" "donnees" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = false
}

# Groupe de sécurité grand ouvert sur Internet.
resource "aws_security_group" "grand_ouvert" {
  name        = "grand-ouvert"
  description = "fixture : ne pas reproduire"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# FAUX secret — sert à vérifier qu'aucun outil ne recopie la valeur dans sa sortie
# (leçon #1 : Bandit renvoyait le credential réel dans issue_text).
# Cette valeur ne doit JAMAIS apparaître dans un rapport ni un finding.
variable "mot_de_passe_admin" {
  description = "faux secret de fixture"
  default     = "FIXTURE-FAKE-SECRET-ne-jamais-ecrire-cette-valeur-9a7f3"
}
