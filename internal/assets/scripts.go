package assets

import _ "embed"

//go:embed apply-iptables.sh
var ApplyIptablesScript string

//go:embed apply-ip6tables.sh
var ApplyIp6tablesScript string

//go:embed apply-nftables.sh
var ApplyNftablesScript string

//go:embed leash_prompt.sh
var LeashPromptScript string
