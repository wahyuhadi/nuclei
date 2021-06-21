package loader

import (
	"fmt"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/projectfile"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/clusterer"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/headless/engine"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/rs/xid"
	"go.uber.org/ratelimit"
)

// Loader is a client for reading templates and parsing them from disk
type Loader struct {
	Templates        []string
	Workflows        []string
	Tags             []string
	ExcludeTags      []string
	ExcludeTemplates []string
}

type Options struct {
	// Output is a writer interface for writing output events from executer.
	Output output.Writer
	// Options contains configuration options for the executer.
	Options *types.Options
	// IssuesClient is a client for nuclei issue tracker reporting
	IssuesClient *reporting.Client
	// Progress is a progress client for scan reporting
	Progress progress.Progress
	// RateLimiter is a rate-limiter for limiting sent number of requests.
	RateLimiter ratelimit.Limiter
	// Catalog is a template catalog implementation for nuclei
	Catalog *catalog.Catalog
	// ProjectFile is the project file for nuclei
	ProjectFile *projectfile.ProjectFile
	// Browser is a browser engine for running headless templates
	Browser *engine.Browser
	// Interactsh is a client for interactsh oob polling server
	Interactsh *interactsh.Client
}

func (l *Loader) loadInputs() {
	// If we have no templates, run on whole template directory with provided tags
	if len(l.Templates) == 0 && len(l.Workflows) == 0 && !r.options.NewTemplates && (len(r.options.Tags) > 0 || len(r.options.ExcludeTags) > 0) {
		r.options.Templates = append(r.options.Templates, r.options.TemplatesDirectory)
	}
	if r.options.NewTemplates {
		templatesLoaded, err := r.readNewTemplatesFile()
		if err != nil {
			gologger.Warning().Msgf("Could not get newly added templates: %s\n", err)
		}
		r.options.Templates = append(r.options.Templates, templatesLoaded...)
	}
	includedTemplates := r.catalog.GetTemplatesPath(r.options.Templates, false)
	excludedTemplates := r.catalog.GetTemplatesPath(r.options.ExcludedTemplates, true)
	// defaults to all templates
	allTemplates := includedTemplates

	if len(excludedTemplates) > 0 {
		excludedMap := make(map[string]struct{}, len(excludedTemplates))
		for _, excl := range excludedTemplates {
			excludedMap[excl] = struct{}{}
		}
		// rebuild list with only non-excluded templates
		allTemplates = []string{}

		for _, incl := range includedTemplates {
			if _, found := excludedMap[incl]; !found {
				allTemplates = append(allTemplates, incl)
			} else {
				gologger.Warning().Msgf("Excluding '%s'", incl)
			}
		}
	}

	// pre-parse all the templates, apply filters
	finalTemplates := []*templates.Template{}

	workflowPaths := r.catalog.GetTemplatesPath(r.options.Workflows, false)
	availableTemplates, _ := r.getParsedTemplatesFor(allTemplates, r.options.Severity, false)
	availableWorkflows, workflowCount := r.getParsedTemplatesFor(workflowPaths, r.options.Severity, true)

	var unclusteredRequests int64 = 0
	for _, template := range availableTemplates {
		// workflows will dynamically adjust the totals while running, as
		// it can't be know in advance which requests will be called
		if len(template.Workflows) > 0 {
			continue
		}
		unclusteredRequests += int64(template.TotalRequests) * r.inputCount
	}

	originalTemplatesCount := len(availableTemplates)
	clusterCount := 0
	clusters := clusterer.Cluster(availableTemplates)
	for _, cluster := range clusters {
		if len(cluster) > 1 && !r.options.OfflineHTTP {
			executerOpts := protocols.ExecuterOptions{
				Output:       r.output,
				Options:      r.options,
				Progress:     r.progress,
				Catalog:      r.catalog,
				RateLimiter:  r.ratelimiter,
				IssuesClient: r.issuesClient,
				Browser:      r.browser,
				ProjectFile:  r.projectFile,
				Interactsh:   r.interactsh,
			}
			clusterID := fmt.Sprintf("cluster-%s", xid.New().String())

			finalTemplates = append(finalTemplates, &templates.Template{
				ID:            clusterID,
				RequestsHTTP:  cluster[0].RequestsHTTP,
				Executer:      clusterer.NewExecuter(cluster, &executerOpts),
				TotalRequests: len(cluster[0].RequestsHTTP),
			})
			clusterCount += len(cluster)
		} else {
			finalTemplates = append(finalTemplates, cluster...)
		}
	}
	for _, workflows := range availableWorkflows {
		finalTemplates = append(finalTemplates, workflows)
	}

	var totalRequests int64 = 0
	for _, t := range finalTemplates {
		if len(t.Workflows) > 0 {
			continue
		}
		totalRequests += int64(t.TotalRequests) * r.inputCount
	}
	if totalRequests < unclusteredRequests {
		gologger.Info().Msgf("Reduced %d requests to %d (%d templates clustered)", unclusteredRequests, totalRequests, clusterCount)
	}
	templateCount := originalTemplatesCount + len(availableWorkflows)

	// 0 matches means no templates were found in directory
	if templateCount == 0 {
		gologger.Fatal().Msgf("Error, no templates were found.\n")
	}
}
