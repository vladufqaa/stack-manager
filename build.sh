#!/usr/bin/env bash
# Сборка stack-manager.sh из модулей src/.
# Источник истины — src/NNN-имя.sh; stack-manager.sh — собранный артефакт.
# Сборка = конкатенация модулей в лексикографическом порядке имён (LC_ALL=C),
# результат обязан совпадать с закоммиченным файлом байт-в-байт (проверяет CI).
set -euo pipefail
cd "$(dirname "$0")"

out="$(mktemp)"
trap 'rm -f "$out"' EXIT
: > "$out"

while IFS= read -r m; do
  cat -- "$m" >> "$out"
done < <(find src -maxdepth 1 -name '[0-9][0-9][0-9]-*.sh' | LC_ALL=C sort)

chmod 755 "$out"
mv -f "$out" stack-manager.sh
echo "stack-manager.sh собран: $(wc -l < stack-manager.sh) строк"
