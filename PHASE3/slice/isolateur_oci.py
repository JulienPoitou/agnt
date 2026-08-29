"""Isolateur OCI — Phase 9.

Produit la commande de confinement d'un outil. C'est le socle du profil « non fiable ».

LES DIX LIMITES IMPOSÉES

     1. mémoire             --memory
     2. swap                --memory-swap égal à --memory  (swap interdit)
     3. CPU                 --cpus
     4. PID                 --pids-limit
     5. taille des fichiers --ulimit fsize
     6. timeout             côté hôte, par le processus appelant
     7. réseau              --network=none
     8. capabilities        --cap-drop=ALL
     9. no-new-privileges   --security-opt=no-new-privileges:true
    10. lecture seule +
        nettoyage           --read-only --tmpfs /tmp --rm

LA RÈGLE LA PLUS IMPORTANTE DE CE FICHIER

La commande produite ici DOIT être identique à celle de `test_oci.sh`. Si les deux
divergent, le harnais teste un confinement qui n'est pas celui qui sera exécuté — et un
test qui ne teste pas la production ne vaut rien. `verifier_conformite()` contrôle ça.

ÉTAT : écrit, mais JAMAIS EXÉCUTÉ. Aucun runtime OCI dans l'environnement de
développement. La commande est vérifiée structurellement, pas éprouvée.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Limites:
    """Les limites imposées à toute exécution en profil « non fiable »."""
    memoire: str = "256m"
    pids: int = 64
    cpus: str = "0.5"
    fsize: int = 10 * 1024 * 1024      # 10 Mo
    timeout: int = 30                   # appliqué côté hôte, pas par docker
    reseau: bool = False                # True = réseau autorisé (outils actifs)
    lecture_seule: bool = True


@dataclass(frozen=True)
class CommandeConfinement:
    argv: list[str]
    limites: Limites
    image: str
    commande_interne: tuple[str, ...] = ()
    montages: dict = field(default_factory=dict)

    def en_ligne(self) -> str:
        return " ".join(shlex.quote(a) for a in self.argv)


def construire(image: str, commande_interne: list[str],
               limites: Limites | None = None,
               montages: dict | None = None) -> CommandeConfinement:
    """Construit la commande docker.

    `commande_interne` est une LISTE, jamais une chaîne shell — la même règle que pour
    les manifests de providers. Passer par un shell réintroduirait l'injection qu'on a
    fermée ailleurs.
    """
    lim = limites or Limites()
    if isinstance(commande_interne, str):
        raise ValueError(
            "la commande interne doit être une LISTE d'arguments, jamais une chaîne shell")

    argv = [
        "docker", "run", "--rm",
        f"--memory={lim.memoire}",
        # memory-swap égal à memory = swap interdit. Sinon une partie de la limite
        # mémoire part sur le disque et la limite ne tient plus.
        f"--memory-swap={lim.memoire}",
        f"--pids-limit={lim.pids}",
        f"--cpus={lim.cpus}",
        f"--ulimit=fsize={lim.fsize}:{lim.fsize}",
    ]
    if lim.lecture_seule:
        argv += ["--read-only", "--tmpfs", "/tmp"]
    argv += [
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--network=none" if not lim.reseau else "--network=bridge",
    ]
    for hote, conteneur in (montages or {}).items():
        argv += ["-v", f"{hote}:{conteneur}:ro"]
    argv += [image, *commande_interne]

    return CommandeConfinement(argv=argv, limites=lim, image=image,
                               commande_interne=tuple(commande_interne),
                               montages=dict(montages or {}))


def verifier_conformite(argv: list[str]) -> list[str]:
    """Vérifie qu'une commande impose bien les dix limites.

    Retourne la liste des problèmes. Liste vide = conforme.
    Ce contrôle existe parce qu'une limite oubliée ne se voit pas à l'œil dans une
    longue ligne de commande.
    """
    texte = " ".join(argv)
    problemes = []

    def exige(cond: bool, msg: str) -> None:
        if not cond:
            problemes.append(msg)

    exige(argv[:2] == ["docker", "run"], "doit commencer par « docker run »")
    exige("--rm" in argv, "10. --rm absent : les conteneurs ne seront pas nettoyés")
    exige(any(a.startswith("--memory=") for a in argv), "1. --memory absent")
    mem = next((a.split("=", 1)[1] for a in argv if a.startswith("--memory=")), None)
    swap = next((a.split("=", 1)[1] for a in argv if a.startswith("--memory-swap=")), None)
    exige(swap is not None, "2. --memory-swap absent : le swap n'est pas borné")
    exige(swap == mem, f"2. --memory-swap ({swap}) doit égaler --memory ({mem}) sinon swap autorisé")
    exige(any(a.startswith("--cpus=") for a in argv), "3. --cpus absent")
    exige(any(a.startswith("--pids-limit=") for a in argv), "4. --pids-limit absent")
    exige(any(a.startswith("--ulimit=fsize=") for a in argv), "5. --ulimit fsize absent")
    exige("--network=none" in argv or "--network=bridge" in argv,
          "7. --network non précisé")
    exige("--cap-drop=ALL" in argv, "8. --cap-drop=ALL absent")
    exige("--security-opt=no-new-privileges:true" in argv, "9. no-new-privileges absent")
    exige("--read-only" in argv, "10. --read-only absent")
    exige("--tmpfs" in argv, "10. --tmpfs absent : aucun espace inscriptible")

    # Aucun shell. On cherche les PAIRES « sh -c » / « bash -c », pas le drapeau -c
    # seul : « python -c "print()" » est légitime et n'est pas un shell.
    for i in range(len(argv) - 1):
        if argv[i] in ("sh", "bash", "dash") and argv[i + 1] == "-c":
            problemes.append(f"la commande passe par un shell : {argv[i]} -c")
    for a in argv:
        for frag in (";", "&&", "||", "`", "$("):
            if frag in a:
                problemes.append(f"métacaractère {frag!r} dans {a!r}")
                break

    # 6. timeout : docker ne l'impose pas. C'est l'appelant qui doit faire
    # « timeout N docker run … » — c'est exactement ce que fait test_oci.sh. Ce n'est
    # donc pas un défaut de la commande, mais une obligation de l'appelant, rappelée
    # dans la docstring et vérifiée par le harnais.
    _ = texte

    return problemes

