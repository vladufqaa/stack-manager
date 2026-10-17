#!/usr/bin/env bash
set -euo pipefail
BASE="${STACK_MANAGER_BASE:-/opt/stack-manager}"
RELEASES="$BASE/releases"
CURRENT="$BASE/current"
BACKUPS="$BASE/backups"
REPO="${STACK_MANAGER_REPO:-vladufqaa/stack-manager}"
API="https://api.github.com/repos/$REPO/releases/latest"
log(){ printf '[+] %s\n' "$*"; }
warn(){ printf '[!] %s\n' "$*" >&2; }
err(){ printf '[x] %s\n' "$*" >&2; }
version(){ [[ -f "$CURRENT/VERSION" ]] && tr -d '[:space:]' < "$CURRENT/VERSION" || echo unknown; }
list_releases(){ [[ -d "$RELEASES" ]] || return 0; find "$RELEASES" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort -V; }
require_tools(){ command -v curl >/dev/null || { err 'нужен curl'; return 1; }; command -v tar >/dev/null || { err 'нужен tar'; return 1; }; command -v sha256sum >/dev/null || { err 'нужен sha256sum'; return 1; }; }
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
  [[ "$(tr -d '[:space:]' < "$src/VERSION")" == "$ver" ]] || { err 'VERSION внутри пакета не совпадает'; return 1; }
  bash -n "$src/stack-manager.sh"
  tmp=$(mktemp -d "$RELEASES/.install.XXXXXX")
  cp -a "$src/." "$tmp/"
  chmod 700 "$tmp/stack-manager.sh"
  rm -rf "$dest"
  mv "$tmp" "$dest"
  ln -sfn "$dest" "$CURRENT"
  log "Установлен релиз $ver"
}
latest_info(){ curl -fsSL --retry 3 --connect-timeout 10 "$API"; }
update(){
  require_tools
  [[ "$(id -u)" == 0 ]] || { err 'update требует root'; return 1; }
  mkdir -p "$RELEASES" "$BACKUPS"
  local json tag ver url sums tmp archive unpack old
  json=$(latest_info) || { err 'не удалось получить latest Release'; return 1; }
  tag=$(printf '%s' "$json" | sed -nE 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' | head -1)
  ver="${tag#v}"
  [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { err "неверный tag: $tag"; return 1; }
  [[ "$(version)" == "$ver" ]] && { log "Уже установлена версия $ver"; return 0; }
  url="$(printf '%s' "$json" | grep -oE '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]+stack-manager-[0-9.]+\.tar\.gz"' | head -1 | sed -E 's/.*"(https:[^"]+)"/\1/')"
  [[ -n "$url" ]] || { err 'в Release нет tar.gz package'; return 1; }
  sums="${url}.sha256"
  tmp=$(mktemp -d /tmp/stack-manager-update.XXXXXX)
  archive="$tmp/stack-manager-$ver.tar.gz"
  curl -fsSL --retry 3 -o "$archive" "$url"
  curl -fsSL --retry 3 -o "$archive.sha256" "$sums"
  (cd "$tmp" && sha256sum -c "$archive.sha256") || { err 'SHA256 package не совпал'; return 1; }
  tar -xzf "$archive" -C "$tmp"
  unpack="$tmp/stack-manager-$ver"
  [[ -d "$unpack" ]] || { err 'в архиве нет каталога release'; return 1; }
  old=$(version)
  [[ "$old" != unknown && -d "$RELEASES/$old" ]] && tar -czf "$BACKUPS/stack-manager-$old-$(date +%Y%m%d-%H%M%S).tar.gz" -C "$RELEASES" "$old" || true
  install_release "$unpack" "$ver"
  bash -n "$CURRENT/stack-manager.sh" || { warn 'новый release не прошёл проверку, откат'; [[ "$old" != unknown ]] && rollback "$old"; return 1; }
  rm -rf "$tmp"
  log "Обновление завершено: $old → $ver"
}
case "${1:-version}" in
  version) echo "Stack Manager $(version)" ;;
  releases) list_releases ;;
  rollback) rollback "${2:-}" ;;
  install) install_release "${2:?Укажи каталог пакета}" "${3:?Укажи версию}" ;;
  update) update ;;
  *) err "Использование: $0 {version|releases|rollback [VERSION]|install DIR VERSION|update}"; exit 2 ;;
esac
