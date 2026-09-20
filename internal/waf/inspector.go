package waf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/7acini/minimal-waf/internal/config"
)

type Detection struct {
	RuleID      string
	Category    string
	Description string
	Location    string
	Parameter   string
}

type Inspector struct {
	rules           []Rule
	maxDecodePasses int
	inspectMethods  map[string]bool
	exclusions      []config.Exclusion
}

func NewInspector(cfg config.WAFConfig) *Inspector {
	enabled := make(map[string]bool, len(cfg.EnabledCategories))
	for _, category := range cfg.EnabledCategories {
		enabled[strings.ToLower(category)] = true
	}
	rules := make([]Rule, 0, len(DefaultRules()))
	for _, rule := range DefaultRules() {
		if enabled[rule.Category] {
			rules = append(rules, rule)
		}
	}
	methods := make(map[string]bool, len(cfg.InspectMethods))
	for _, method := range cfg.InspectMethods {
		methods[strings.ToUpper(method)] = true
	}
	return &Inspector{
		rules:           rules,
		maxDecodePasses: cfg.MaxDecodePasses,
		inspectMethods:  methods,
		exclusions:      cfg.Exclusions,
	}
}

func (i *Inspector) InspectRequest(request *http.Request, body []byte) []Detection {
	detections := i.inspectValue("path", "", request.URL.EscapedPath())
	queryValues, queryErr := url.ParseQuery(request.URL.RawQuery)
	for name, values := range queryValues {
		detections = append(detections, i.inspectValue("query_name", name, name)...)
		for _, value := range values {
			detections = append(detections, i.inspectValue("query", name, value)...)
		}
	}
	// Inspect the raw query only when parsing fails, catching malformed encodings
	// without creating unscoped duplicates that would defeat parameter exclusions.
	if queryErr != nil && request.URL.RawQuery != "" {
		detections = append(detections, i.inspectValue("raw_query", "", request.URL.RawQuery)...)
	}
	if len(body) > 0 && i.inspectMethods[strings.ToUpper(request.Method)] {
		detections = append(detections, i.inspectBody(request.Header.Get("Content-Type"), body)...)
	}
	return i.filterExclusions(request, deduplicate(detections))
}

func (i *Inspector) inspectBody(contentType string, body []byte) []Detection {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	}
	switch mediaType {
	case "application/x-www-form-urlencoded":
		values, parseErr := url.ParseQuery(string(body))
		if parseErr != nil {
			return i.inspectValue("body", "", string(body))
		}
		return i.inspectValues("form", values)
	case "application/json", "application/ld+json":
		var value any
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return i.inspectValue("body", "", string(body))
		}
		return i.inspectJSON(value, "", 0)
	case "multipart/form-data":
		boundary := params["boundary"]
		if boundary == "" {
			return i.inspectValue("body", "", string(body))
		}
		return i.inspectMultipart(body, boundary)
	default:
		if utf8.Valid(body) {
			return i.inspectValue("body", "", string(body))
		}
		return nil
	}
}

func (i *Inspector) inspectValues(location string, values url.Values) []Detection {
	var detections []Detection
	for name, entries := range values {
		detections = append(detections, i.inspectValue(location+"_name", name, name)...)
		for _, value := range entries {
			detections = append(detections, i.inspectValue(location, name, value)...)
		}
	}
	return detections
}

func (i *Inspector) inspectJSON(value any, path string, depth int) []Detection {
	if depth > 32 {
		return nil
	}
	var detections []Detection
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			childPath := key
			if path != "" {
				childPath = path + "." + key
			}
			detections = append(detections, i.inspectValue("json_name", childPath, key)...)
			detections = append(detections, i.inspectJSON(child, childPath, depth+1)...)
		}
	case []any:
		for index, child := range typed {
			detections = append(detections, i.inspectJSON(child, fmt.Sprintf("%s[%d]", path, index), depth+1)...)
		}
	case string:
		detections = append(detections, i.inspectValue("json", path, typed)...)
	}
	return detections
}

func (i *Inspector) inspectMultipart(body []byte, boundary string) []Detection {
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	var detections []Detection
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return append(detections, i.inspectValue("body", "", string(body))...)
		}
		name := part.FormName()
		detections = append(detections, i.inspectValue("multipart_name", name, name)...)
		if filename := part.FileName(); filename != "" {
			detections = append(detections, i.inspectValue("filename", name, filename)...)
			continue
		}
		value, err := io.ReadAll(part)
		if err == nil && utf8.Valid(value) {
			detections = append(detections, i.inspectValue("multipart", name, string(value))...)
		}
	}
	return detections
}

func (i *Inspector) inspectValue(location, parameter, value string) []Detection {
	normalized := normalize(value, i.maxDecodePasses)
	var detections []Detection
	for _, rule := range i.rules {
		if rule.Match(normalized) {
			detections = append(detections, Detection{
				RuleID: rule.ID, Category: rule.Category, Description: rule.Description,
				Location: location, Parameter: parameter,
			})
		}
	}
	return detections
}

func normalize(value string, passes int) string {
	value = html.UnescapeString(value)
	for range passes {
		decoded, err := url.QueryUnescape(value)
		if err != nil || decoded == value {
			break
		}
		value = html.UnescapeString(decoded)
	}
	value = strings.ReplaceAll(value, `\`, "/")
	value = strings.ReplaceAll(value, "\x00", "")
	return strings.ToLower(value)
}

func (i *Inspector) filterExclusions(request *http.Request, detections []Detection) []Detection {
	filtered := detections[:0]
	for _, detection := range detections {
		excluded := false
		for _, exclusion := range i.exclusions {
			if strings.HasPrefix(request.URL.Path, exclusion.PathPrefix) &&
				matchesOrEmpty(exclusion.Methods, request.Method) &&
				matchesOrEmpty(exclusion.Parameters, detection.Parameter) &&
				matchesOrEmpty(exclusion.Categories, detection.Category) {
				excluded = true
				break
			}
		}
		if !excluded {
			filtered = append(filtered, detection)
		}
	}
	return filtered
}

func matchesOrEmpty(values []string, candidate string) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if strings.EqualFold(value, candidate) {
			return true
		}
	}
	return false
}

func deduplicate(input []Detection) []Detection {
	seen := make(map[string]bool, len(input))
	output := make([]Detection, 0, len(input))
	for _, detection := range input {
		key := detection.RuleID + "\x00" + detection.Location + "\x00" + detection.Parameter
		if !seen[key] {
			seen[key] = true
			output = append(output, detection)
		}
	}
	return output
}
