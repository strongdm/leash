package policy

// DefaultCedarPolicy is the permissive bootstrap policy expressed in Cedar.
// It allows read/write/open across the filesystem, process execution, and
// outbound network connections to any host. This mirrors the historical
// permissive IR we used for first-boot.
const DefaultCedarPolicy = `
permit (principal, action in [Action::"FileOpen", Action::"FileOpenReadOnly", Action::"FileOpenReadWrite"], resource)
when { resource in [ Dir::"/" ] };

permit (principal, action == Action::"ProcessExec", resource)
when { resource in [ Dir::"/" ] };

permit (principal, action == Action::"NetworkConnect", resource)
when { resource in [ Host::"*" ] };`

// DefaultCedar returns the permissive bootstrap Cedar policy.
func DefaultCedar() string { return DefaultCedarPolicy }
