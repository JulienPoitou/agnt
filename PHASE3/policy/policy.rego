# Policy engine — règles de décision.
#
# Rôle : OPA DÉCIDE, le code Python APPLIQUE. Aucune règle de sécurité ne doit vivre
# dans le moteur Python, sinon il existe deux autorités et la seconde est contournable.
#
# Ces règles sont évaluables SANS LLM : c'est le test qui prouve que la frontière de
# sécurité est déterministe (MASTER_PROMPT §5.1, « AI != Security Boundary »).
#
# DEUX PIÈGES D'OPA RENCONTRÉS POUR DE VRAI :
#   1. `cap` est un mot réservé (cardinalité d'ensemble) : ne pas l'utiliser comme variable.
#   2. un champ d'entrée nommé `capabilities` est ignoré par OPA (il a son propre concept
#      de capabilities). Vérifié : trois copies identiques du même tableau, seul le champ
#      `capabilities` renvoie undefined. D'où le nom `capability_ids` côté politique.
#   3. une variable liée uniquement en position de clé (`k[x] := ...` avec x non lié dans
#      le corps) est refusée : d'où l'ensemble de couples plutôt qu'un index.

package plateforme.autorisation

import rego.v1

# ------------------------------------------------------------------ refus par défaut
# Rien n'est autorisé sauf ce qui est explicitement permis ci-dessous.
default allow := false

# Risques acceptés sans validation humaine.
risques_acceptes := {"PASSIVE", "ACTIVE"}

# Un plan est autorisé si TOUTES les conditions tiennent.
allow if {
	not memoire_insuffisante
	not durcissement_insuffisant
	count(input.plan.steps) > 0
	every step in input.plan.steps {
		step.risque in risques_acceptes
		step.provider in input.registre.providers
		step.capability in input.registre.capability_ids
		couples[[step.capability, step.provider]]
		target_compatible(step)
	}
	input.plan.registre_empreinte == input.registre.empreinte
	input.cible.autorisee == true
	not commande_suspecte
	not provider_binding_suspect
}

# ------------------------------------------------------------------ motifs de refus
# Chaque refus est nommé, pour que le rapport puisse dire POURQUOI c'est refusé.
motifs contains "plan_vide" if {
	count(input.plan.steps) == 0
}

motifs contains "risque_trop_eleve" if {
	some step in input.plan.steps
	not step.risque in risques_acceptes
}

motifs contains "provider_inconnu" if {
	some step in input.plan.steps
	not step.provider in input.registre.providers
}

motifs contains "capability_inconnue" if {
	some step in input.plan.steps
	not step.capability in input.registre.capability_ids
}

motifs contains "provider_hors_capacite" if {
	some step in input.plan.steps
	not couples[[step.capability, step.provider]]
}

motifs contains "registre_divergent" if {
	input.plan.registre_empreinte != input.registre.empreinte
}

motifs contains "cible_non_autorisee" if {
	not input.cible.autorisee
}

motifs contains "commande_suspecte" if {
	commande_suspecte
}

# Un provider MCP n'est pas autorisé par la seule présence d'un identifiant dans le
# plan. Le binding (capability, serveur, outil, transport et confiance) doit être
# identique à celui du registre. La réponse de `tools/list` n'entre jamais dans cette
# décision : elle est une observation, pas une autorité.
binding_correspondant(step) if {
	some p in input.registre.providers_detail
	p.id == step.provider
	p.capability == step.capability
	p.transport == "mcp"
	p.identity.server_id == step.server_id
	p.identity.tool == step.tool
	p.identity.protocol_version == step.protocol_version
	p.identity.trust == step.trust
}

provider_binding_suspect if {
	some step in input.plan.steps
	step.transport == "mcp"
	not binding_correspondant(step)
}

motifs contains "binding_provider_externe_invalide" if {
	provider_binding_suspect
}

# La cible est une donnée typée de l'orchestrateur, pas un chemin réinterprété par
# le serveur. Les providers locaux restent couverts par la garde de chemin historique.
target_compatible(step) if {
	step.transport != "mcp"
}

target_compatible(step) if {
	step.transport == "mcp"
	input.cible.type in step.target_types
}

target_incompatible if {
	some step in input.plan.steps
	step.transport == "mcp"
	not target_compatible(step)
}

motifs contains "cible_incompatible_provider_externe" if {
	target_incompatible
}

# ------------------------------------------------------------------ garde de ressources
# Le moteur DÉCLARE son profil ; OPA DÉCIDE. Cette règle existe pour qu'une limite
# d'environnement interdise une utilisation dangereuse, au lieu d'être seulement
# documentée quelque part.
#
# Vérifié : la mémoire n'est PAS bornée dans cet environnement (RLIMIT_AS casse Trivy
# et Gitleaks, et cgroups v2 n'est pas accessible sans root). Donc :
#     pas de mémoire bornée → pas de dépôt non fiable, pas d'outil actif.

memoire_insuffisante if {
	input.cible.confiance == "untrusted"
	not input.profil_sandbox.memoire_bornee
}

motifs contains "memoire_non_bornee_cible_non_fiable" if {
	memoire_insuffisante
}

durcissement_insuffisant if {
	some step in input.plan.steps
	step.risque in {"ACTIVE", "INTRUSIVE", "DESTRUCTIVE"}
	not input.profil_sandbox.durci
}

motifs contains "sandbox_non_durci_outil_actif" if {
	durcissement_insuffisant
}

# ------------------------------------------------------------------ garde anti-shell
# Le plan ne doit contenir QUE des commandes issues du registre. Cette règle est une
# seconde barrière, indépendante de la construction du plan : même si un bug du moteur
# laissait passer une chaîne forgée, elle serait refusée ici.
commande_suspecte if {
	some step in input.plan.steps
	some elem in array.concat(step.commande, step.args)
	some frag in fragments_interdits
	contains(elem, frag)
}

fragments_interdits := {
	";", "&&", "||", "|", "`", "$(", ">", "<", "\n",
	"sh -c", "bash -c", "/bin/sh", "/bin/bash", "curl", "wget", "nc ",
}

# ------------------------------------------------------------------ index du registre
# Ensemble des couples (capacité, provider) réellement déclarés. Construit depuis le
# registre, jamais en dur. On utilise un ensemble de tableaux plutôt qu'un index
# clé -> valeur : OPA refuse une variable liée uniquement en position de clé.
couples[[c.id, p]] := true if {
	some c in input.registre.capabilities_detail
	some p in c.providers
}

# ------------------------------------------------------------------ compte-rendu
decision := {
	"allow": allow,
	"motifs": motifs,
}

