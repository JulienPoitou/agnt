#!/bin/bash
# Fixture shellcheck — défauts VOLONTAIRES, ne pas corriger (voir README.md).
# Défauts choisis stables entre versions shellcheck : variables non quotées,
# rm -rf sur variable non protégée, cd sans garde, usage de ls parsé.

REPERTOIRE=$1

rm -rf $REPERTOIRE/tmp

cd /tmp
total=$(ls | wc -l)

if [ $total -gt 5 ]
then
  echo beaucoup
fi

echo $REPERTOIRE
