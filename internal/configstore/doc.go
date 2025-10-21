// Package configstore provides helpers for persisting leash configuration in
// an XDG-compliant location. Decisions about whether to mount host config
// directories resolve using project scope before global scope; absent explicit
// configuration the caller should prompt the user or skip mounting.
package configstore
