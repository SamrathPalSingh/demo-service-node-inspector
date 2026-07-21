package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type publishConfig struct {
	MarkdownFile string
	MarkdownKey  string
	ObservedKey  string
	Target       string
	Observed     []string
	ContractID   string
	ContractName string
	Owner        string
	Repository   string
	Contact      string
}

type publishedRule struct {
	ID           string   `json:"id"`
	Severity     string   `json:"severity"`
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	Requirements []string `json:"requirements"`
	Signals      []string `json:"signals,omitempty"`
	Remediation  string   `json:"remediation"`
	Shorthand    bool     `json:"-"`
}

type contractDocument struct {
	SchemaVersion  string            `json:"schema_version"`
	Kind           string            `json:"kind"`
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Owner          string            `json:"owner"`
	Repository     string            `json:"repository"`
	Contact        string            `json:"contact,omitempty"`
	SourceRevision string            `json:"source_revision"`
	Rules          []publishedRule   `json:"rules"`
	Markdown       string            `json:"-"`
	Observed       map[string]string `json:"-"`
}

type parseSection int

const (
	sectionNone parseSection = iota
	sectionMetadata
	sectionRequirements
	sectionRemediation
	sectionSignals
)

var client = &http.Client{Timeout: 60 * time.Second}

func main() {
	kind := flag.String("kind", environment("PUBLISH_KIND", ""), "service or platform")
	output := flag.String("output", "", "write generated JSON locally instead of publishing")
	flag.Parse()
	if err := publish(*kind, *output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func publish(kind, output string) error {
	settings, err := settingsFor(kind)
	if err != nil {
		return err
	}
	document, err := buildDocument(kind, settings)
	if err != nil {
		return err
	}
	encoded, _ := json.MarshalIndent(documentForJSON(document, settings), "", "  ")
	encoded = append(encoded, '\n')

	if output != "" {
		if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil && filepath.Dir(output) != "." {
			return err
		}
		if err := os.WriteFile(output, encoded, 0o644); err != nil {
			return err
		}
		fmt.Printf("Generated %s from %s.\n", output, settings.MarkdownFile)
		return nil
	}

	repository := os.Getenv("REGISTRY_REPO")
	token := os.Getenv("REGISTRY_WRITE_TOKEN")
	if repository == "" || token == "" {
		return errors.New("REGISTRY_REPO and REGISTRY_WRITE_TOKEN are required when --output is not used")
	}
	branch := environment("REGISTRY_BRANCH", "main")
	current, err := getCurrent(repository, settings.Target, branch, token)
	if err != nil {
		return err
	}
	shortRevision := document.SourceRevision
	if len(shortRevision) > 7 {
		shortRevision = shortRevision[:7]
	}
	body := map[string]any{
		"message": fmt.Sprintf("chore(contracts): publish %s %s", kind, shortRevision),
		"content": base64.StdEncoding.EncodeToString(encoded),
		"branch":  branch,
	}
	if current != "" {
		body["sha"] = current
	}
	if err := githubRequest(http.MethodPut, fmt.Sprintf("/repos/%s/contents/%s", repository, settings.Target), token, body, nil); err != nil {
		return err
	}
	fmt.Printf("Published %s to %s.\n", settings.Target, repository)
	return nil
}

func buildDocument(kind string, settings publishConfig) (contractDocument, error) {
	markdown, err := os.ReadFile(settings.MarkdownFile)
	if err != nil {
		return contractDocument{}, err
	}
	expectedKind := map[string]string{"service": "service-requirements", "platform": "platform-invariants"}[kind]
	defaults := contractDocument{
		SchemaVersion: "1.0",
		Kind:          expectedKind,
		ID:            settings.ContractID,
		Name:          settings.ContractName,
		Owner:         settings.Owner,
		Repository:    settings.Repository,
		Contact:       settings.Contact,
	}
	document, err := parseContractMarkdown(string(markdown), defaults)
	if err != nil {
		return contractDocument{}, fmt.Errorf("parse %s: %w", settings.MarkdownFile, err)
	}
	if document.Kind != expectedKind {
		return contractDocument{}, fmt.Errorf("contract kind %q does not match --kind %s", document.Kind, kind)
	}
	document.Markdown = string(markdown)
	document.SourceRevision = environment("GITHUB_SHA", "local")
	document.Observed = map[string]string{}
	for _, name := range settings.Observed {
		data, readErr := os.ReadFile(name)
		if readErr != nil {
			return contractDocument{}, readErr
		}
		document.Observed[name] = string(data)
	}
	return document, nil
}

func documentForJSON(document contractDocument, settings publishConfig) map[string]any {
	result := map[string]any{
		"schema_version":     document.SchemaVersion,
		"kind":               document.Kind,
		"id":                 document.ID,
		"name":               document.Name,
		"owner":              document.Owner,
		"repository":         document.Repository,
		"source_revision":    document.SourceRevision,
		"rules":              document.Rules,
		settings.MarkdownKey: document.Markdown,
		settings.ObservedKey: document.Observed,
	}
	if document.Contact != "" {
		result["contact"] = document.Contact
	}
	return result
}

func parseContractMarkdown(markdown string, defaults contractDocument) (contractDocument, error) {
	document := defaults
	var currentRule *publishedRule
	section := sectionNone
	severity := ""
	metadata := map[string]string{}
	seenIDs := map[string]bool{}

	for lineNumber, rawLine := range strings.Split(strings.ReplaceAll(markdown, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "# ") {
			document.Name = contractNameFromHeading(strings.TrimSpace(strings.TrimPrefix(line, "# ")))
			continue
		}
		if strings.HasPrefix(line, "Owned by ") {
			parseOwnership(line, &document)
			continue
		}
		if line == "## Contract metadata" {
			section = sectionMetadata
			severity = ""
			currentRule = nil
			continue
		}
		if strings.HasPrefix(line, "## ") {
			candidate := strings.TrimSuffix(strings.ToLower(strings.TrimPrefix(line, "## ")), " severity")
			if _, ok := map[string]bool{"critical": true, "high": true, "medium": true, "low": true}[candidate]; ok {
				severity = candidate
				section = sectionNone
				currentRule = nil
			}
			continue
		}
		if strings.HasPrefix(line, "### ") {
			if severity == "" {
				return document, fmt.Errorf("line %d: rule is outside a severity section", lineNumber+1)
			}
			parts := strings.SplitN(strings.TrimPrefix(line, "### "), " - ", 2)
			if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
				return document, fmt.Errorf("line %d: rule heading must be '### RULE-ID - Title'", lineNumber+1)
			}
			id := strings.TrimSpace(parts[0])
			if seenIDs[id] {
				return document, fmt.Errorf("line %d: duplicate rule ID %s", lineNumber+1, id)
			}
			seenIDs[id] = true
			document.Rules = append(document.Rules, publishedRule{ID: id, Severity: severity, Title: strings.TrimSpace(parts[1]), Requirements: []string{}, Signals: []string{}})
			currentRule = &document.Rules[len(document.Rules)-1]
			section = sectionNone
			continue
		}
		if strings.HasPrefix(line, "#### ") {
			if currentRule == nil {
				return document, fmt.Errorf("line %d: rule subsection appears before a rule", lineNumber+1)
			}
			switch strings.ToLower(strings.TrimPrefix(line, "#### ")) {
			case "requirements":
				section = sectionRequirements
			case "remediation":
				section = sectionRemediation
			case "deterministic signals":
				section = sectionSignals
			default:
				return document, fmt.Errorf("line %d: unsupported rule subsection %q", lineNumber+1, line)
			}
			continue
		}
		if !strings.HasPrefix(line, "- ") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, "- "))
		if section == sectionMetadata {
			parts := strings.SplitN(value, ":", 2)
			if len(parts) != 2 {
				return document, fmt.Errorf("line %d: metadata must be '- Key: value'", lineNumber+1)
			}
			metadata[strings.ToLower(strings.TrimSpace(parts[0]))] = stripCode(strings.TrimSpace(parts[1]))
			continue
		}
		if currentRule == nil {
			if severity != "" {
				document.Rules = append(document.Rules, publishedRule{
					Severity:     severity,
					Requirements: []string{value},
					Signals:      []string{},
					Shorthand:    true,
				})
			}
			continue
		}
		switch section {
		case sectionRequirements:
			currentRule.Requirements = append(currentRule.Requirements, value)
		case sectionRemediation:
			if currentRule.Remediation != "" {
				currentRule.Remediation += " "
			}
			currentRule.Remediation += value
		case sectionSignals:
			currentRule.Signals = append(currentRule.Signals, stripCode(value))
		}
	}

	document.SchemaVersion = firstNonEmpty(metadata["schema version"], document.SchemaVersion)
	document.Kind = firstNonEmpty(metadata["kind"], document.Kind)
	document.ID = firstNonEmpty(metadata["contract id"], document.ID)
	document.Name = firstNonEmpty(metadata["name"], document.Name)
	document.Owner = firstNonEmpty(metadata["owner"], document.Owner)
	document.Repository = firstNonEmpty(metadata["repository"], document.Repository)
	document.Contact = firstNonEmpty(metadata["contact"], document.Contact)
	if document.SchemaVersion == "" || document.Kind == "" || document.ID == "" || document.Name == "" || document.Owner == "" || document.Repository == "" {
		return document, errors.New("metadata requires Schema version, Kind, Contract ID, Name, Owner, and Repository")
	}
	if len(document.Rules) == 0 {
		return document, errors.New("contract must declare at least one rule")
	}
	enrichShorthandRules(document.ID, document.Rules)
	seenIDs = map[string]bool{}
	for index := range document.Rules {
		rule := &document.Rules[index]
		if rule.ID == "" {
			return document, fmt.Errorf("rule %d has no ID", index+1)
		}
		if seenIDs[rule.ID] {
			return document, fmt.Errorf("duplicate rule ID %s", rule.ID)
		}
		seenIDs[rule.ID] = true
		if len(rule.Requirements) == 0 {
			return document, fmt.Errorf("rule %s has no requirements", rule.ID)
		}
		if rule.Remediation == "" {
			return document, fmt.Errorf("rule %s has no remediation", rule.ID)
		}
		rule.Description = strings.Join(rule.Requirements, " ")
	}
	sort.SliceStable(document.Rules, func(i, j int) bool {
		order := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
		return order[document.Rules[i].Severity] < order[document.Rules[j].Severity]
	})
	return document, nil
}

func parseOwnership(line string, document *contractDocument) {
	ownerPart, contactPart, hasContact := strings.Cut(strings.TrimSpace(line), ". Contact:")
	owner := strings.TrimSpace(strings.TrimPrefix(ownerPart, "Owned by "))
	document.Owner = stripCode(strings.TrimSuffix(owner, "."))
	if hasContact {
		contact := strings.TrimSuffix(strings.TrimSpace(contactPart), ".")
		document.Contact = stripCode(contact)
	}
}

func contractNameFromHeading(heading string) string {
	lower := strings.ToLower(heading)
	for _, suffix := range []string{" infrastructure requirements", " infrastructure contract", " requirements", " contract"} {
		if strings.HasSuffix(lower, suffix) {
			return strings.TrimSpace(heading[:len(heading)-len(suffix)])
		}
	}
	return heading
}

func enrichShorthandRules(contractID string, rules []publishedRule) {
	for index := range rules {
		rule := &rules[index]
		if !rule.Shorthand {
			continue
		}
		requirement := rule.Requirements[0]
		lower := strings.ToLower(requirement)
		switch {
		case strings.Contains(lower, "nat egress") && strings.Contains(lower, "34.120.10.10"):
			rule.ID = "SEARCH-NET-001"
			rule.Title = "Preserve vendor allow-listed NAT egress addresses"
			rule.Remediation = "Keep static NAT allocation and both documented IP addresses."
			rule.Signals = []string{"allocation_method:\\s*ephemeral", "nat_ip_mode:\\s*dynamic", "addresses\\s*=\\s*\\[\\]"}
		case strings.Contains(lower, "public ip") && strings.Contains(lower, "34.98.20.5"):
			rule.ID = "SEARCH-ING-001"
			rule.Title = "Preserve the public ingress address"
			rule.Remediation = "Retain 34.98.20.5 or coordinate migration of legacy clients first."
			rule.Signals = []string{"address:\\s*dynamic", "loadBalancerIP:\\s*dynamic"}
		case strings.Contains(lower, "fast-ssd") && strings.Contains(lower, "iops"):
			rule.ID = "SEARCH-STO-001"
			rule.Title = "Preserve cache-index storage performance"
			rule.Remediation = "Provide at least 3,000 IOPS for fast-ssd."
			rule.Signals = []string{"iops:\\s*(\\d{1,3}|[12]\\d{3})\\b", "provisioned_iops\\s*=\\s*(\\d{1,3}|[12]\\d{3})\\b"}
		default:
			sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(requirement))))
			rule.ID = fmt.Sprintf("%s-AUTO-%X", strings.ToUpper(contractID), sum[:4])
			rule.Title = "Preserve declared infrastructure requirement"
			rule.Remediation = "Restore or preserve the declared requirement."
		}
	}
}

func firstNonEmpty(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func stripCode(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && strings.HasPrefix(value, "`") && strings.HasSuffix(value, "`") {
		return strings.TrimSuffix(strings.TrimPrefix(value, "`"), "`")
	}
	return value
}

func settingsFor(kind string) (publishConfig, error) {
	switch kind {
	case "service":
		return publishConfig{
			MarkdownFile: "infra-requirements.md", MarkdownKey: "requirements_markdown", ObservedKey: "observed_manifests",
			Target:     "contracts/services/node-inspector.json",
			Observed:   []string{"cmd/node-inspector/main.go", "k8s/deployment.yaml"},
			ContractID: "node-inspector", ContractName: "Node Inspector", Owner: "runtime-observability-team",
			Repository: "demo-service-node-inspector", Contact: "#runtime-observability",
		}, nil
	case "platform":
		return publishConfig{
			MarkdownFile: "platform-invariants.md", MarkdownKey: "invariants_markdown", ObservedKey: "observed_state",
			Target:     "contracts/platform/shared-platform.json",
			Observed:   []string{"infra/storage-class.yaml", "infra/network-state.yaml", "terraform/main.tf"},
			ContractID: "shared-platform", ContractName: "Shared Kubernetes Platform", Owner: "platform-engineering",
			Repository: "demo-infra-platform", Contact: "#platform-engineering",
		}, nil
	default:
		return publishConfig{}, errors.New("--kind must be service or platform")
	}
}

func getCurrent(repository, target, branch, token string) (string, error) {
	var response struct {
		SHA string `json:"sha"`
	}
	route := fmt.Sprintf("/repos/%s/contents/%s?ref=%s", repository, target, url.QueryEscape(branch))
	err := githubRequest(http.MethodGet, route, token, nil, &response)
	if err != nil && strings.Contains(err.Error(), "(404)") {
		return "", nil
	}
	return response.SHA, err
}

func githubRequest(method, route, token string, input, output any) error {
	var body io.Reader
	if input != nil {
		encoded, _ := json.Marshal(input)
		body = bytes.NewReader(encoded)
	}
	request, _ := http.NewRequest(method, "https://api.github.com"+route, body)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("User-Agent", "infra-contract-poc")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("GitHub API %s %s failed (%d): %.400s", method, route, response.StatusCode, data)
	}
	if output != nil && len(data) > 0 {
		return json.Unmarshal(data, output)
	}
	return nil
}

func environment(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
