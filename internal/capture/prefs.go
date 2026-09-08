package capture

import (
	"fmt"
	"strings"
)

// nsGlobalAllowlist is the curated set of NSGlobalDomain keys worth moving.
//
// NSGlobalDomain is never exported wholesale. It is a junk drawer holding
// hundreds of keys, many of them machine-specific (screen geometry, saved panel
// state) or locale-derived, and importing the whole domain onto a different Mac
// reliably breaks something subtle. These are the behavioural preferences people
// actually notice the absence of.
var nsGlobalAllowlist = []string{
	"AppleInterfaceStyle",
	"AppleInterfaceStyleSwitchesAutomatically",
	"ApplePressAndHoldEnabled",
	"InitialKeyRepeat",
	"KeyRepeat",
	"AppleKeyboardUIMode",
	"AppleShowAllExtensions",
	"AppleShowScrollBars",
	"AppleScrollerPagingBehavior",
	"com.apple.swipescrolldirection",
	"com.apple.springing.enabled",
	"com.apple.springing.delay",
	"NSAutomaticCapitalizationEnabled",
	"NSAutomaticDashSubstitutionEnabled",
	"NSAutomaticPeriodSubstitutionEnabled",
	"NSAutomaticQuoteSubstitutionEnabled",
	"NSAutomaticSpellingCorrectionEnabled",
	"NSNavPanelExpandedStateForSaveMode",
	"PMPrintingExpandedStateForPrint",
	"NSTableViewDefaultSizeMode",
	"AppleFontSmoothing",
	"NSWindowResizeTime",
	"AppleMenuBarVisibleInFullscreen",
}

// ExportDomain exports one preference domain as XML.
func ExportDomain(domain string) ([]byte, bool) {
	out, ok := run("defaults", "export", domain, "-")
	if !ok || strings.TrimSpace(out) == "" {
		return nil, false
	}
	return []byte(out), true
}

// ExportNSGlobal builds a plist containing only the allowlisted global keys.
//
// It is assembled key by key rather than exported and filtered, so a key that is
// not on the list cannot reach the bundle even by accident.
func ExportNSGlobal() ([]byte, int) {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n<dict>\n")

	found := 0
	for _, key := range nsGlobalAllowlist {
		value, ok := run("defaults", "read", "-g", key)
		if !ok {
			continue
		}
		typ, _ := run("defaults", "read-type", "-g", key)
		found++
		fmt.Fprintf(&b, "\t<key>%s</key>\n\t%s\n", escapeXML(key), plistValue(typ, value))
	}
	b.WriteString("</dict>\n</plist>\n")
	if found == 0 {
		return nil, 0
	}
	return []byte(b.String()), found
}

// plistValue renders a defaults value as a plist element.
func plistValue(typ, value string) string {
	switch {
	case strings.Contains(typ, "boolean"):
		if value == "1" || strings.EqualFold(value, "true") {
			return "<true/>"
		}
		return "<false/>"
	case strings.Contains(typ, "integer"):
		return "<integer>" + escapeXML(value) + "</integer>"
	case strings.Contains(typ, "float"):
		return "<real>" + escapeXML(value) + "</real>"
	default:
		return "<string>" + escapeXML(value) + "</string>"
	}
}

func escapeXML(s string) string {
	return strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;",
	).Replace(s)
}

// NSGlobalKeys exposes the allowlist for documentation and tests.
func NSGlobalKeys() []string { return append([]string(nil), nsGlobalAllowlist...) }
