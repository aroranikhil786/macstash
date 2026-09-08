package catalog

import (
	"encoding/json"
	"io/fs"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The JSON schema is what editors and external contributors validate against, so
// it has to stay in step with the Go types. A schema that has drifted is worse
// than none: it tells a contributor their entry is fine right up until CI
// disagrees.
func TestEntriesConformToSchema(t *testing.T) {
	raw, err := os.ReadFile("schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("schema.json is not valid JSON: %v", err)
	}

	allowed := propertyNames(schema)
	if len(allowed) == 0 {
		t.Fatal("could not read top-level properties from schema.json")
	}

	files, err := fs.Glob(entriesFS, "entries/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		data, err := entriesFS.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := yaml.Unmarshal(data, &doc); err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		for key := range doc {
			if !allowed[key] {
				t.Errorf("%s: key %q is not in schema.json — either a typo or the schema needs updating", f, key)
			}
		}
		checkNested(t, f, schema, doc)
	}
}

// checkNested walks capture/detect/restore against their schema definitions,
// which is where typos actually happen — a misspelled "quite_first" would
// otherwise be silently ignored by the YAML decoder and the app would never be
// quit before restore.
func checkNested(t *testing.T, file string, schema, doc map[string]any) {
	t.Helper()
	props, _ := schema["properties"].(map[string]any)
	for _, section := range []string{"detect", "restore", "capture"} {
		sub, ok := doc[section].(map[string]any)
		if !ok {
			continue
		}
		def, ok := props[section].(map[string]any)
		if !ok {
			continue
		}
		allowed := propertyNames(def)
		for key := range sub {
			if !allowed[key] {
				t.Errorf("%s: %s.%s is not in schema.json", file, section, key)
			}
		}
	}
}

func propertyNames(schema map[string]any) map[string]bool {
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]bool, len(props))
	for k := range props {
		out[k] = true
	}
	return out
}

// Every class named in the schema must be one the classifier understands.
func TestSchemaClassesMatchCode(t *testing.T) {
	raw, err := os.ReadFile("schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"never"`) && !strings.Contains(string(raw), "never is not permitted") {
		t.Error("schema.json appears to allow class never; a catalog entry must never declare it")
	}
}
