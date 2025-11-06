#!/usr/bin/env sh
# shellcheck shell=sh

_leash_prompt_main() {
  # Respect opt-out and avoid double-initialization.
  if [ "${LEASH_PROMPT_DISABLE:-0}" = "1" ]; then
    return
  fi
  if [ "${LEASH_PROMPT_INITIALIZED:-0}" = "1" ]; then
    return
  fi

  # Only run in interactive shells.
  case ${-:-} in
  *i*) ;;
  *)
    if [ -z "${PS1-}" ] && [ -z "${ZSH_VERSION-}" ]; then
      return
    fi
    ;;
  esac

  LEASH_PROMPT_SHELL="sh"
  if [ -n "${BASH_VERSION-}" ]; then
    LEASH_PROMPT_SHELL="bash"
  elif [ -n "${ZSH_VERSION-}" ]; then
    LEASH_PROMPT_SHELL="zsh"
  elif [ -n "${KSH_VERSION-}" ]; then
    LEASH_PROMPT_SHELL="ksh"
  elif [ -n "${SHELL-}" ]; then
    LEASH_PROMPT_SHELL=$(basename "${SHELL}")
  fi

LEASH_PROMPT_COLOR_MODE=$(_leash_prompt_detect_color_mode)

  case ${LEASH_PROMPT_SHELL} in
  zsh)
    _leash_prompt_install_zsh
    ;;
  bash)
    _leash_prompt_install_bash_like
    ;;
  dash)
    _leash_prompt_install_bash_like
    ;;
  ksh|mksh|ksh93)
    _leash_prompt_install_ksh
    ;;
  *)
    _leash_prompt_install_bash_like
    ;;
  esac

  LEASH_PROMPT_INITIALIZED=1
  export LEASH_PROMPT_INITIALIZED
}

_leash_prompt_detect_utf8() {
  encoding="${LC_ALL:-${LC_CTYPE:-${LANG:-}}}"
  case $encoding in
  *[Uu][Tt][Ff]-8*|*[Uu][Tt][Ff]8*)
  export LEASH_PROMPT_UTF8=1
    ;;
  *)
  export LEASH_PROMPT_UTF8=0
    ;;
  esac
}

_leash_prompt_detect_color_mode() {
  if [ "${LEASH_PROMPT_MONO:-0}" = "1" ]; then
    printf 'mono'
    return
  fi
  if [ "${LEASH_PROMPT_FORCE_ANSI8:-0}" = "1" ]; then
    printf 'ansi8'
    return
  fi
  if [ -n "${COLORTERM-}" ]; then
    case $COLORTERM in
    *[Tt][Rr][Uu][Ee][Cc][Oo][Ll][Oo][Rr]*|*[24][Bb][Ii][Tt]*)
      printf 'rgb'
      return
      ;;
    esac
  fi
  if command -v tput >/dev/null 2>&1; then
    colors=$(tput colors 2>/dev/null || printf '0')
    case $colors in
    "" )
      ;;
    *[!0-9]*)
      ;;
    *)
      if [ "$colors" -ge 256 ]; then
        printf 'rgb'
        return
      fi
      if [ "$colors" -ge 16 ]; then
        printf 'ansi8'
        return
      fi
      ;;
    esac
  fi
  printf 'ansi8'
}

_leash_prompt_sanitize() {
  value=$1
  if [ -z "${value-}" ]; then
    printf 'agent\n'
    return
  fi
  value=$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')
  value=$(printf '%s' "$value" | LC_ALL=C sed 's/[^a-z0-9_-]/-/g')
  value=$(printf '%s' "$value" | sed 's/-\{2,\}/-/g')
  value=$(printf '%s' "$value" | sed 's/^-//;s/-$//')
  value=$(printf '%.63s' "$value")
  if [ -z "$value" ]; then
    value="agent"
  fi
  printf '%s\n' "$value"
}

_leash_prompt_project_source() {
  if [ -n "${LEASH_PROJECT-}" ]; then
    printf '%s\n' "$LEASH_PROJECT"
    return
  fi
  if [ -n "${LEASH_WORKSPACE-}" ]; then
    printf '%s\n' "$LEASH_WORKSPACE"
    return
  fi
  dir=${PWD:-}
  if [ -n "$dir" ]; then
    candidate=${dir##*/}
    if [ -n "$candidate" ] && [ "$candidate" != "." ] && [ "$candidate" != "/" ]; then
      printf '%s\n' "$candidate"
      return
    fi
  fi
  printf 'agent\n'
}

_leash_prompt_project() {
  if [ -n "${LEASH_PROMPT_PROJECT-}" ]; then
    printf '%s\n' "$LEASH_PROMPT_PROJECT"
    return
  fi
  candidate=$(_leash_prompt_project_source)
  sanitized=$(_leash_prompt_sanitize "$candidate")
  LEASH_PROMPT_PROJECT=$sanitized
  export LEASH_PROMPT_PROJECT
  printf '%s\n' "$LEASH_PROMPT_PROJECT"
}

_leash_prompt_project_display() {
  if [ -n "${LEASH_PROMPT_PROJECT_DISPLAY-}" ]; then
    printf '%s\n' "$LEASH_PROMPT_PROJECT_DISPLAY"
    return
  fi
  display=$(_leash_prompt_project_source)
  if [ -z "$display" ]; then
    display="agent"
  fi
  LEASH_PROMPT_PROJECT_DISPLAY=$display
  printf '%s\n' "$LEASH_PROMPT_PROJECT_DISPLAY"
}

_leash_prompt_dir() {
  dir=${PWD:-}
  if [ -z "$dir" ]; then
    printf '?\n'
    return
  fi
  if [ "$dir" = "/" ]; then
    printf '/\n'
    return
  fi

  if [ -n "${HOME-}" ]; then
    case $dir in
    "$HOME")
      printf '~\n'
      return
      ;;
    "$HOME"/*)
      trimmed=${dir#"$HOME"/}
      printf '%s\n' "$trimmed" | awk '
        BEGIN { OFS="/"; home="~/"; }
        {
          n = split($0, parts, "/")
          if (n <= 0) {
            print "~"
          } else if (n == 1) {
            print home parts[1]
          } else {
            print home parts[n-1] "/" parts[n]
          }
        }
      '
      return
      ;;
    esac
  fi

  trimmed=${dir#/}
  printf '%s\n' "$trimmed" | awk '
    BEGIN { OFS="/"; }
    {
      n = split($0, parts, "/")
      if (n <= 0) {
        print "/"
      } else if (n == 1) {
        print parts[1]
      } else {
        print parts[n-1] "/" parts[n]
      }
    }
  '
}

_leash_prompt_set_wrappers() {
  case $1 in
  zsh)
    LEASH_PROMPT_WRAP_OPEN='%{'
    LEASH_PROMPT_WRAP_CLOSE='%}'
    ;;
  bash|dash|ksh|mksh|ksh93)
    LEASH_PROMPT_WRAP_OPEN=$(printf '\001')
    LEASH_PROMPT_WRAP_CLOSE=$(printf '\002')
    ;;
  raw)
    LEASH_PROMPT_WRAP_OPEN=''
    LEASH_PROMPT_WRAP_CLOSE=''
    ;;
  *)
    LEASH_PROMPT_WRAP_OPEN=$(printf '\001')
    LEASH_PROMPT_WRAP_CLOSE=$(printf '\002')
    ;;
  esac
}

_leash_prompt_make_seq() {
  code=$1
  if [ -z "$code" ]; then
    printf ''
    return
  fi
  if [ -n "$LEASH_PROMPT_WRAP_OPEN" ]; then
    printf '%s\033[%sm%s' "$LEASH_PROMPT_WRAP_OPEN" "$code" "$LEASH_PROMPT_WRAP_CLOSE"
  else
    printf '\033[%sm' "$code"
  fi
}

_leash_prompt_color() {
  key=$1
  mode=${LEASH_PROMPT_COLOR_MODE:-ansi8}
  case $mode in
  mono)
    printf ''
    ;;
  rgb)
    case $key in
    label_l) _leash_prompt_make_seq '38;2;129;97;246' ;;
    label_e) _leash_prompt_make_seq '38;2;164;99;247' ;;
    label_a) _leash_prompt_make_seq '38;2;200;102;247' ;;
    label_s) _leash_prompt_make_seq '38;2;237;106;248' ;;
    label_h) _leash_prompt_make_seq '38;2;239;141;249' ;;
    accent) _leash_prompt_make_seq '38;2;176;79;233' ;;
    project) _leash_prompt_make_seq '38;2;230;236;250' ;;
    dir) _leash_prompt_make_seq '38;2;147;161;184' ;;
    symbol_ok) _leash_prompt_make_seq '38;2;120;235;173' ;;
    symbol_err) _leash_prompt_make_seq '38;2;255;95;86' ;;
    reset) _leash_prompt_make_seq '0' ;;
    *) printf '' ;;
    esac
    ;;
  ansi8)
    case $key in
    label_l) _leash_prompt_make_seq '38;5;135' ;;
    label_e) _leash_prompt_make_seq '38;5;171' ;;
    label_a) _leash_prompt_make_seq '38;5;207' ;;
    label_s) _leash_prompt_make_seq '38;5;213' ;;
    label_h) _leash_prompt_make_seq '38;5;219' ;;
    accent) _leash_prompt_make_seq '38;5;205' ;;
    project) _leash_prompt_make_seq '38;5;250' ;;
    dir) _leash_prompt_make_seq '38;5;246' ;;
    symbol_ok) _leash_prompt_make_seq '38;5;48' ;;
    symbol_err) _leash_prompt_make_seq '38;5;203' ;;
    reset) _leash_prompt_make_seq '0' ;;
    *) printf '' ;;
    esac
    ;;
  *)
    printf ''
    ;;
  esac
}

_leash_prompt_label() {
  c1=$(_leash_prompt_color 'label_l')
  c2=$(_leash_prompt_color 'label_e')
  c3=$(_leash_prompt_color 'label_a')
  c4=$(_leash_prompt_color 'label_s')
  c5=$(_leash_prompt_color 'label_h')
  reset=$(_leash_prompt_color 'reset')
  printf '%s[%sl%se%sa%ss%sh%s]%s' "$c1" "$c1" "$c2" "$c3" "$c4" "$c5" "$c5" "$reset"
}

_leash_prompt_render() {
  shell_mode=$1
  exit_status=$2

  _leash_prompt_set_wrappers "$shell_mode"

  label=$(_leash_prompt_label)
  project_display=$(_leash_prompt_project_display)
  project_color=$(_leash_prompt_color 'project')
  reset=$(_leash_prompt_color 'reset')
  : "$(_leash_prompt_project)"

  bracketed=$label
  if [ "$exit_status" -eq 0 ] 2>/dev/null; then
    symbol_color=$(_leash_prompt_color 'symbol_ok')
    symbol_text='>'
  else
    symbol_color=$(_leash_prompt_color 'symbol_err')
    symbol_text='>!'
  fi
  symbol="${symbol_color}${symbol_text}${reset}"

  result="${bracketed} ${project_color}${project_display}${reset} ${symbol} "
  printf '%s' "$result"
}

_leash_prompt_debug() {
  if [ "${LEASH_PROMPT_DEBUG:-0}" = "1" ]; then
    printf '[leash-prompt] %s\n' "$*" >&2
  fi
}

_leash_prompt_install_bash_like() {
  _leash_prompt_debug "install bash-like prompt for ${LEASH_PROMPT_SHELL}"

  _leash_prompt_prompt_command() {
    leash_status=$?
    PS1=$(_leash_prompt_render 'bash' "$leash_status")
  }

  if [ -n "${BASH_VERSION-}" ]; then
    export -f _leash_prompt_prompt_command >/dev/null 2>&1 || true
  fi

  if [ -n "${PROMPT_COMMAND-}" ]; then
    PROMPT_COMMAND="_leash_prompt_prompt_command;${PROMPT_COMMAND}"
  else
    PROMPT_COMMAND="_leash_prompt_prompt_command"
  fi
  export PROMPT_COMMAND
}

_leash_prompt_install_zsh() {
  _leash_prompt_debug "install zsh prompt"

  _leash_prompt_precmd() {
    zsh_status=$?
    # shellcheck disable=SC2034
    PROMPT=$(_leash_prompt_render 'zsh' "$zsh_status")
  }

  if command -v add-zsh-hook >/dev/null 2>&1; then
    add-zsh-hook precmd _leash_prompt_precmd
  else
    precmd_functions=${precmd_functions:-}
    found=0
    for fn in $precmd_functions; do
      if [ "$fn" = "_leash_prompt_precmd" ]; then
        found=1
        break
      fi
    done
    if [ "$found" -ne 1 ]; then
      precmd_functions="$precmd_functions _leash_prompt_precmd"
      eval "precmd_functions=($precmd_functions)"
    fi
  fi
}

_leash_prompt_install_ksh() {
  _leash_prompt_debug "install ksh prompt"

  _leash_prompt_ksh_hook() {
    ksh_status=$?
    PS1=$(_leash_prompt_render 'bash' "$ksh_status")
  }

  # shellcheck disable=SC3047
  trap '_leash_prompt_ksh_hook' DEBUG
  PS1=$(_leash_prompt_render 'bash' 0)
  export PS1
}

_leash_prompt_main "$@"

_leash_prompt_cleanup() {
  for fn in \
    _leash_prompt_main \
    _leash_prompt_install_bash_like \
    _leash_prompt_install_zsh \
    _leash_prompt_install_ksh \
    _leash_prompt_cleanup
  do
    unset -f "$fn" 2>/dev/null || true
  done
}

_leash_prompt_cleanup
