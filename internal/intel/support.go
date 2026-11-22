package intel

import (
	"context"
	"net/url"
	"strings"
)

// Support says whether a version's release line still receives fixes. A
// version that is out of support has no advisory telling you so: flaws found
// in it are simply never fixed.
type Support struct {
	Status string `json:"status" jsonschema:"supported, end_of_life or unknown"`
	// ReleaseLine is the line the version belongs to, such as 16 or 1.31.
	ReleaseLine  string `json:"releaseLine,omitempty"`
	EndOfLife    string `json:"endOfLife,omitempty" jsonschema:"date the release line stops, or stopped, receiving fixes"`
	LatestInLine string `json:"latestInLine,omitempty" jsonschema:"newest release on the same release line"`
	Detail       string `json:"detail,omitempty"`
}

// The possible values of Support.Status.
const (
	SupportSupported = "supported"
	SupportEnded     = "end_of_life"
	SupportUnknown   = "unknown"
)

type lifecycleRelease struct {
	Name    string `json:"name"`
	IsEOL   bool   `json:"isEol"`
	EOLFrom string `json:"eolFrom"`
	Latest  *struct {
		Name string `json:"name"`
	} `json:"latest"`
}

// support looks the component's version up in endoflife.date's lifecycle
// data. It also returns the newest release overall, which serves as the
// latest version for products with no other source for it.
func (c *Client) support(ctx context.Context, component Component) (support Support, latest string, err error) {
	var data struct {
		Result struct {
			Releases []lifecycleRelease `json:"releases"`
		} `json:"result"`
	}
	lifecycleURL := c.Endpoints.Lifecycle + "/" + url.PathEscape(component.Lifecycle) + "/"
	if _, err := c.fetch(ctx, request{url: lifecycleURL, ttl: ttlLifecycle}, &data); err != nil {
		return Support{Status: SupportUnknown}, "", err
	}
	releases := data.Result.Releases
	// Releases are listed newest first.
	if len(releases) > 0 && releases[0].Latest != nil {
		latest = releases[0].Latest.Name
	}
	if component.Version == "" {
		return Support{Status: SupportUnknown, Detail: "no version was given"}, latest, nil
	}

	// A version belongs to the release line whose name it starts with:
	// 16.4 to "16", 1.31.2 to "1.31". The longest such name wins.
	running := strings.TrimLeft(component.Version, "vV")
	var line *lifecycleRelease
	for i := range releases {
		name := releases[i].Name
		if running != name && !strings.HasPrefix(running, name+".") && !strings.HasPrefix(running, name+"-") {
			continue
		}
		if line == nil || len(name) > len(line.Name) {
			line = &releases[i]
		}
	}
	if line == nil {
		return Support{Status: SupportUnknown, Detail: "this version's release line is not in the lifecycle data"}, latest, nil
	}
	support = Support{Status: SupportSupported, ReleaseLine: line.Name, EndOfLife: line.EOLFrom}
	if line.IsEOL {
		support.Status = SupportEnded
	}
	if line.Latest != nil {
		support.LatestInLine = line.Latest.Name
	}
	return support, latest, nil
}
