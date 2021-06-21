package loader

import (
	"fmt"
	"strings"

	"github.com/karrick/godirwalk"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// getParsedTemplatesFor parse the specified templates and returns a slice of the parsable ones, optionally filtered
// by severity, along with a flag indicating if workflows are present.
func (r *Runner) getParsedTemplatesFor(templatePaths, severities []string, workflows bool) (parsedTemplates map[string]*templates.Template, workflowCount int) {
	filterBySeverity := len(severities) > 0

	if !workflows {
		gologger.Info().Msgf("Loading templates...")
	} else {
		gologger.Info().Msgf("Loading workflows...")
	}

	parsedTemplates = make(map[string]*templates.Template)
	for _, match := range templatePaths {
		t, err := r.parseTemplateFile(match)
		if err != nil {
			gologger.Warning().Msgf("Could not parse file '%s': %s\n", match, err)
			continue
		}
		if t == nil {
			continue
		}
		if len(t.Workflows) == 0 && workflows {
			continue // don't print if user only wants to run workflows
		}
		if len(t.Workflows) > 0 && !workflows {
			continue // don't print workflow if user only wants to run templates
		}
		if len(t.Workflows) > 0 {
			workflowCount++
		}
		sev := strings.ToLower(types.ToString(t.Info["severity"]))
		if !filterBySeverity || hasMatchingSeverity(sev, severities) {
			parsedTemplates[t.ID] = t
			gologger.Info().Msgf("%s\n", r.templateLogMsg(t.ID, types.ToString(t.Info["name"]), types.ToString(t.Info["author"]), sev))
		} else {
			gologger.Warning().Msgf("Excluding template %s due to severity filter (%s not in [%s])", t.ID, sev, severities)
		}
	}
	return parsedTemplates, workflowCount
}

// parseTemplateFile returns the parsed template file
func (l *Loader) parseTemplateFile(file string) (*templates.Template, error) {
	executerOpts := protocols.ExecuterOptions{
		Output:       l.options.output,
		Options:      l.options.options,
		Progress:     l.options.progress,
		Catalog:      l.options.catalog,
		IssuesClient: l.options.issuesClient,
		RateLimiter:  l.options.ratelimiter,
		Interactsh:   l.options.interactsh,
		ProjectFile:  l.options.projectFile,
		Browser:      l.options.browser,
	}
	template, err := templates.Parse(file, executerOpts)
	if err != nil {
		return nil, err
	}
	if template == nil {
		return nil, nil
	}
	return template, nil
}

func (r *Runner) templateLogMsg(id, name, author, severity string) string {
	// Display the message for the template
	message := fmt.Sprintf("[%s] %s (%s)",
		r.colorizer.BrightBlue(id).String(),
		r.colorizer.Bold(name).String(),
		r.colorizer.BrightYellow("@"+author).String())
	if severity != "" {
		message += " [" + r.severityColors.Data[severity] + "]"
	}
	return message
}

func hasMatchingSeverity(templateSeverity string, allowedSeverities []string) bool {
	for _, s := range allowedSeverities {
		finalSeverities := []string{}
		if strings.Contains(s, ",") {
			finalSeverities = strings.Split(s, ",")
		} else {
			finalSeverities = append(finalSeverities, s)
		}

		for _, sev := range finalSeverities {
			sev = strings.ToLower(sev)
			if sev != "" && strings.HasPrefix(templateSeverity, sev) {
				return true
			}
		}
	}
	return false
}

func directoryWalker(fsPath string, callback func(fsPath string, d *godirwalk.Dirent) error) error {
	err := godirwalk.Walk(fsPath, &godirwalk.Options{
		Callback: callback,
		ErrorCallback: func(fsPath string, err error) godirwalk.ErrorAction {
			return godirwalk.SkipNode
		},
		Unsorted: true,
	})

	// directory couldn't be walked
	if err != nil {
		return err
	}

	return nil
}
