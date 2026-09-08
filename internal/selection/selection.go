// Package selection lets a person prune what macstash carries or applies, by
// editing a file rather than answering prompts.
//
// The alternative designs were a numbered prompt and a checkbox TUI. Both fall
// down at the scale this actually runs at: the first real machine tested had 46
// applications and 45 repositories, and neither arrow-keying through 45 items
// nor typing "1,3,12-15" against a numbered list is something anyone wants to do
// twice. An editor buffer is the tool people already use for exactly this
// shape of task — `git rebase -i`, `git add -e`, editing a Brewfile — it scales
// to any length, and the result is a file that can be saved, diffed and reused
// on the next migration.
//
// It also costs no dependency. A checkbox interface needs raw terminal mode;
// this needs an exec.
package selection

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Item is one selectable thing.
type Item struct {
	// Key identifies the item and is what the file round-trips. It must be
	// stable between a render and a parse, so it is never derived from anything
	// that could be reformatted.
	Key string
	// Note is shown to the right of the key and is not part of the identity.
	Note string
	// Selected is whether the item is currently included.
	Selected bool
}

// Category is a named group of items, rendered as one section.
type Category struct {
	Name string
	// Help is printed above the section as a comment. This is where a category
	// explains what excluding something actually costs.
	Help  string
	Items []Item
}

// Document is everything offered for selection in one editing pass.
type Document struct {
	Categories []Category
}

// Empty reports whether there is nothing to select.
func (d Document) Empty() bool {
	for _, c := range d.Categories {
		if len(c.Items) > 0 {
			return false
		}
	}
	return true
}

// Counts returns how many items are selected and how many exist.
func (d Document) Counts() (selected, total int) {
	for _, c := range d.Categories {
		for _, it := range c.Items {
			total++
			if it.Selected {
				selected++
			}
		}
	}
	return selected, total
}

// Selected reports the chosen keys per category.
func (d Document) Selected() map[string]map[string]bool {
	out := make(map[string]map[string]bool, len(d.Categories))
	for _, c := range d.Categories {
		keys := make(map[string]bool, len(c.Items))
		for _, it := range c.Items {
			keys[it.Key] = it.Selected
		}
		out[c.Name] = keys
	}
	return out
}

const header = `# macstash selection
#
# Every line below is included. Comment a line out with '#', or delete it, to
# leave that item behind. Save and quit when you are done.
#
# Deleting everything, or emptying the file, cancels the operation — that is
# the safe way out if you opened this by mistake.
`

// Render writes the document in the editable format.
func Render(d Document) []byte {
	var b bytes.Buffer
	b.WriteString(header)

	for _, c := range d.Categories {
		if len(c.Items) == 0 {
			continue
		}
		b.WriteString("\n")
		if c.Help != "" {
			for _, line := range strings.Split(strings.TrimSpace(c.Help), "\n") {
				fmt.Fprintf(&b, "# %s\n", line)
			}
		}
		fmt.Fprintf(&b, "[%s]\n", c.Name)

		width := 0
		for _, it := range c.Items {
			if it.Note != "" && len(it.Key) > width {
				width = len(it.Key)
			}
		}
		for _, it := range c.Items {
			prefix := "  "
			if !it.Selected {
				prefix = "# "
			}
			if it.Note == "" {
				fmt.Fprintf(&b, "%s%s\n", prefix, it.Key)
				continue
			}
			fmt.Fprintf(&b, "%s%-*s   %s\n", prefix, width, it.Key, it.Note)
		}
	}
	return b.Bytes()
}

// sectionLine matches a category header.
var sectionLine = regexp.MustCompile(`^\s*\[([^\]]+)\]\s*$`)

// Parse reads an edited file back, returning the keys left enabled per category.
//
// An item that was deleted outright counts as deselected, because deleting a
// line is what people actually do in an editor. A key that does not correspond
// to anything offered is an error rather than a shrug: a typo would otherwise
// silently drop whatever it was meant to name, and a selection that quietly
// omits something is the exact failure this tool exists to prevent.
func Parse(data []byte, offered Document) (Document, error) {
	known := map[string]map[string]int{}
	for ci, c := range offered.Categories {
		byKey := make(map[string]int, len(c.Items))
		for ii := range c.Items {
			byKey[c.Items[ii].Key] = ii
		}
		known[c.Name] = byKey
		_ = ci
	}

	// Start from everything deselected; the file says what survives.
	result := Document{Categories: make([]Category, len(offered.Categories))}
	copy(result.Categories, offered.Categories)
	for ci := range result.Categories {
		items := make([]Item, len(offered.Categories[ci].Items))
		copy(items, offered.Categories[ci].Items)
		for ii := range items {
			items[ii].Selected = false
		}
		result.Categories[ci].Items = items
	}
	index := map[string]int{}
	for ci, c := range result.Categories {
		index[c.Name] = ci
	}

	section := ""
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for line := 1; scanner.Scan(); line++ {
		text := scanner.Text()
		trimmed := strings.TrimSpace(text)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if m := sectionLine.FindStringSubmatch(text); m != nil {
			section = m[1]
			if _, ok := known[section]; !ok {
				return Document{}, fmt.Errorf("line %d: unknown section %q", line, section)
			}
			continue
		}
		if section == "" {
			return Document{}, fmt.Errorf("line %d: %q appears before any [section]", line, trimmed)
		}
		key := splitKey(trimmed)
		ii, ok := known[section][key]
		if !ok {
			return Document{}, fmt.Errorf(
				"line %d: %q is not something macstash offered under [%s]; "+
					"comment lines out rather than editing them", line, key, section)
		}
		result.Categories[index[section]].Items[ii].Selected = true
	}
	if err := scanner.Err(); err != nil {
		return Document{}, err
	}
	return result, nil
}

// splitKey takes the key from a rendered line. Notes are separated by two or
// more spaces, so keys containing single spaces — which most application names
// do — survive intact.
func splitKey(line string) string {
	if i := strings.Index(line, "   "); i >= 0 {
		return strings.TrimSpace(line[:i])
	}
	if i := strings.Index(line, "  "); i >= 0 {
		return strings.TrimSpace(line[:i])
	}
	return strings.TrimSpace(line)
}

// ErrCancelled is returned when the file came back with nothing selected.
var ErrCancelled = fmt.Errorf("selection cancelled: nothing was left enabled")

// Edit renders the document, opens it in the user's editor and parses the
// result.
//
// dir is where the file is written, so a caller can keep it somewhere the user
// can find again rather than in a temporary directory.
func Edit(d Document, dir string) (Document, error) {
	if d.Empty() {
		return d, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Document{}, err
	}
	path := filepath.Join(dir, "selection.conf")
	if err := os.WriteFile(path, Render(d), 0o600); err != nil {
		return Document{}, err
	}

	if err := launchEditor(path); err != nil {
		return Document{}, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Document{}, err
	}
	edited, err := Parse(data, d)
	if err != nil {
		return Document{}, fmt.Errorf("%w\n\nThe file is still at %s if you want to fix it and "+
			"re-run with --selection %s", err, path, path)
	}
	if selected, _ := edited.Counts(); selected == 0 {
		return Document{}, ErrCancelled
	}
	return edited, nil
}

// Load reads a previously saved selection file.
func Load(path string, offered Document) (Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Document{}, err
	}
	return Parse(data, offered)
}

// launchEditor runs $VISUAL, $EDITOR, or vi, attached to the terminal.
func launchEditor(path string) error {
	editor := firstNonEmpty(os.Getenv("VISUAL"), os.Getenv("EDITOR"), "vi")

	// Editors are routinely configured as a command with flags — "code -w",
	// "subl -w" — so the value is split rather than executed whole.
	fields := strings.Fields(editor)
	if len(fields) == 0 {
		return fmt.Errorf("no editor: set $EDITOR")
	}
	bin, err := exec.LookPath(fields[0])
	if err != nil {
		return fmt.Errorf("cannot run editor %q: %w\nSet $EDITOR, or edit %s by hand and re-run with --selection %s",
			fields[0], err, path, path)
	}

	args := append(append([]string{}, fields[1:]...), path)
	cmd := exec.Command(bin, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("editor exited with an error, so nothing was changed: %w", err)
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
