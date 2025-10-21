package assets

import _ "embed"

//go:embed apply-iptables.sh
var ApplyIptablesScript string

//go:embed leash_prompt.sh
var LeashPromptScript string
