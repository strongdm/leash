package ui

import "strings"

// ComposeTitle builds the Control UI <title> string based on optional project and command info.
// Empty values are omitted from the final string.
func ComposeTitle(project, command string) string {
	base := "Leash"
	if project = strings.TrimSpace(project); project != "" {
		base += " | " + project
	}
	if command = strings.TrimSpace(command); command != "" {
		base += " > " + command
	}
	return base
}
