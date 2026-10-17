#!/usr/bin/env bash
set -euo pipefail
BASE=/opt/stack-manager
RELEASES="$BASE/releases"
CURRENT="$BASE/current"
VERSION_FILE="$BASE/current/VERSION"
REPO="${STACK_MANAGER_REPO:-https://github.com/vladufqaa/stack-manager.git}"
log(){ printf '[+] %s\n' "$*"; }
err(){ printf '[x] %s\n' "$*" >&2; }
version(){ [[ -f "$VERSION_FILE" ]] && cat "$VERSION_FILE" || echo unknown; }
list_releases(){ [[ -d "$RELEASES" ]] || return 0; find "$RELEASES" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort -V; }
rollback(){
  local target="${1:-}" previous
  [[ -n "$target" ]] || { previous=$(list_releases | tail -2 | head -1); target="$previous"; }
  [[ -d "$RELEASES/$target" ]] || { err "Релиз не найден: $target"; return 1; }
  ln -sfn "$RELEASES/$target" "$CURRENT"
  log "Активирован релиз $target"
}
install_release(){
  local src="$1" ver="$2" dest="$RELEASES/$ver" tmp
  [[ -f "$src/stack-manager.sh" && -f "$src/VERSION" ]] || { err 'В пакете нет stack-manager.sh или VERSION'; return 1; }
  bash -n "$src/stack-manager.sh"
  tmp=$(mktemp -d "$RELEASES/.install.XXXXXX")
  cp -a "$src/." "$tmp/"
  chmod 700 "$tmp/stack-manager.sh"
  mv "$tmp" "$dest"
  ln -sfn "$dest" "$CURRENT"
  log "Установлен релиз $ver"
}
case "${1:-version}" in
  version) echo "Stack Manager $(version)" ;;
  releases) list_releases ;;
  rollback) rollback "${2:-}" ;;
  install) install_release "${2:?Укажи каталог пакета}" "${3:?Укажи версию}" ;;
  update) err 'Автоматическое обновление по сети будет добавлено после публикации Releases'; exit 2 ;;
  *) err "Использование: $0 {version|releases|rollback [VERSION]|install DIR VERSION|update}"; exit 2 ;;
esac
