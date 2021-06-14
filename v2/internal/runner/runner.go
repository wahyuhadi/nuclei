package runner

import (
	"bufio"
	"os"
	"path"
	"strings"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/nuclei/v2/internal/collaborator"
	"github.com/projectdiscovery/nuclei/v2/internal/colorizer"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/projectfile"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/headless/engine"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/exporters/disk"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/remeh/sizedwaitgroup"
	"go.uber.org/atomic"
	"go.uber.org/ratelimit"
	"gopkg.in/yaml.v2"
)

// Runner is a client for running the enumeration process.
type Runner struct {
	hostMap         *hybrid.HybridMap
	output          output.Writer
	interactsh      *interactsh.Client
	inputCount      int64
	templatesConfig *nucleiConfig
	options         *types.Options
	projectFile     *projectfile.ProjectFile
	catalog         *catalog.Catalog
	progress        progress.Progress
	colorizer       aurora.Aurora
	issuesClient    *reporting.Client
	severityColors  *colorizer.Colorizer
	browser         *engine.Browser
	ratelimiter     ratelimit.Limiter
}

// New creates a new client for running enumeration process.
func New(options *types.Options) (*Runner, error) {
	runner := &Runner{
		options: options,
	}
	if options.Headless {
		browser, err := engine.New(options)
		if err != nil {
			return nil, err
		}
		runner.browser = browser
	}
	if err := runner.updateTemplates(); err != nil {
		gologger.Warning().Msgf("Could not update templates: %s\n", err)
	}
	// Read nucleiignore file if given a templateconfig
	if runner.templatesConfig != nil {
		runner.readNucleiIgnoreFile()
	}
	runner.catalog = catalog.New(runner.options.TemplatesDirectory)
	runner.catalog.AppendIgnore(runner.templatesConfig.IgnorePaths)

	var reportingOptions *reporting.Options
	if options.ReportingConfig != "" {
		file, err := os.Open(options.ReportingConfig)
		if err != nil {
			gologger.Fatal().Msgf("Could not open reporting config file: %s\n", err)
		}

		reportingOptions = &reporting.Options{}
		if parseErr := yaml.NewDecoder(file).Decode(reportingOptions); parseErr != nil {
			file.Close()
			gologger.Fatal().Msgf("Could not parse reporting config file: %s\n", parseErr)
		}
		file.Close()
	}
	if options.DiskExportDirectory != "" {
		if reportingOptions != nil {
			reportingOptions.DiskExporter = &disk.Options{Directory: options.DiskExportDirectory}
		} else {
			reportingOptions = &reporting.Options{}
			reportingOptions.DiskExporter = &disk.Options{Directory: options.DiskExportDirectory}
		}
	}
	if reportingOptions != nil {
		if client, err := reporting.New(reportingOptions, options.ReportingDB); err != nil {
			gologger.Fatal().Msgf("Could not create issue reporting client: %s\n", err)
		} else {
			runner.issuesClient = client
		}
	}

	// output coloring
	useColor := !options.NoColor
	runner.colorizer = aurora.NewAurora(useColor)
	runner.severityColors = colorizer.New(runner.colorizer)

	if options.TemplateList {
		runner.listAvailableTemplates()
		os.Exit(0)
	}

	if (len(options.Templates) == 0 || !options.NewTemplates || (options.Targets == "" && !options.Stdin && options.Target == "")) && options.UpdateTemplates {
		os.Exit(0)
	}
	if hm, err := hybrid.New(hybrid.DefaultDiskOptions); err != nil {
		gologger.Fatal().Msgf("Could not create temporary input file: %s\n", err)
	} else {
		runner.hostMap = hm
	}

	runner.inputCount = 0
	dupeCount := 0

	// Handle single target
	if options.Target != "" {
		runner.inputCount++
		// nolint:errcheck // ignoring error
		runner.hostMap.Set(options.Target, nil)
	}

	// Handle stdin
	if options.Stdin {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			url := strings.TrimSpace(scanner.Text())
			if url == "" {
				continue
			}
			if _, ok := runner.hostMap.Get(url); ok {
				dupeCount++
				continue
			}
			runner.inputCount++
			// nolint:errcheck // ignoring error
			runner.hostMap.Set(url, nil)
		}
	}

	// Handle taget file
	if options.Targets != "" {
		input, err := os.Open(options.Targets)
		if err != nil {
			gologger.Fatal().Msgf("Could not open targets file '%s': %s\n", options.Targets, err)
		}
		scanner := bufio.NewScanner(input)
		for scanner.Scan() {
			url := strings.TrimSpace(scanner.Text())
			if url == "" {
				continue
			}
			if _, ok := runner.hostMap.Get(url); ok {
				dupeCount++
				continue
			}
			runner.inputCount++
			// nolint:errcheck // ignoring error
			runner.hostMap.Set(url, nil)
		}
		input.Close()
	}

	if dupeCount > 0 {
		gologger.Info().Msgf("Supplied input was automatically deduplicated (%d removed).", dupeCount)
	}

	// Create the output file if asked
	outputWriter, err := output.NewStandardWriter(!options.NoColor, options.NoMeta, options.JSON, options.Output, options.TraceLogFile)
	if err != nil {
		gologger.Fatal().Msgf("Could not create output file '%s': %s\n", options.Output, err)
	}
	runner.output = outputWriter

	// Creates the progress tracking object
	var progressErr error
	runner.progress, progressErr = progress.NewStatsTicker(options.StatsInterval, options.EnableProgressBar, options.Metrics, options.MetricsPort)
	if progressErr != nil {
		return nil, progressErr
	}

	// create project file if requested or load existing one
	if options.Project {
		var projectFileErr error
		runner.projectFile, projectFileErr = projectfile.New(&projectfile.Options{Path: options.ProjectPath, Cleanup: options.ProjectPath == ""})
		if projectFileErr != nil {
			return nil, projectFileErr
		}
	}

	if !options.NoInteractsh {
		interactshClient, err := interactsh.New(&interactsh.Options{
			ServerURL:      options.InteractshURL,
			CacheSize:      int64(options.InteractionsCacheSize),
			Eviction:       time.Duration(options.InteractionsEviction) * time.Second,
			ColldownPeriod: time.Duration(options.InteractionsColldownPeriod) * time.Second,
			PollDuration:   time.Duration(options.InteractionsPollDuration) * time.Second,
			Output:         runner.output,
			IssuesClient:   runner.issuesClient,
			Progress:       runner.progress,
		})
		if err != nil {
			gologger.Error().Msgf("Could not create interactsh client: %s", err)
		} else {
			runner.interactsh = interactshClient
		}
	}

	// Enable Polling
	if options.BurpCollaboratorBiid != "" {
		collaborator.DefaultCollaborator.Collab.AddBIID(options.BurpCollaboratorBiid)
	}

	if options.RateLimit > 0 {
		runner.ratelimiter = ratelimit.New(options.RateLimit)
	} else {
		runner.ratelimiter = ratelimit.NewUnlimited()
	}
	return runner, nil
}

// Close releases all the resources and cleans up
func (r *Runner) Close() {
	if r.output != nil {
		r.output.Close()
	}
	r.hostMap.Close()
	if r.projectFile != nil {
		r.projectFile.Close()
	}
	protocolinit.Close()
}

// RunEnumeration sets up the input layer for giving input nuclei.
// binary and runs the actual enumeration
func (r *Runner) RunEnumeration() {
	defer r.Close()

	gologger.Info().Msgf("Using %s rules (%s templates, %s workflows)",
		r.colorizer.Bold(templateCount).String(),
		r.colorizer.Bold(templateCount-workflowCount).String(),
		r.colorizer.Bold(workflowCount).String())

	results := &atomic.Bool{}
	wgtemplates := sizedwaitgroup.New(r.options.TemplateThreads)
	// Starts polling or ignore
	collaborator.DefaultCollaborator.Poll()

	// tracks global progress and captures stdout/stderr until p.Wait finishes
	r.progress.Init(r.inputCount, templateCount, totalRequests)

	for _, t := range finalTemplates {
		wgtemplates.Add()
		go func(template *templates.Template) {
			defer wgtemplates.Done()

			if len(template.Workflows) > 0 {
				results.CAS(false, r.processWorkflowWithList(template))
			} else {
				results.CAS(false, r.processTemplateWithList(template))
			}
		}(t)
	}
	wgtemplates.Wait()

	if r.interactsh != nil {
		matched := r.interactsh.Close()
		if matched {
			results.CAS(false, true)
		}
	}
	r.progress.Stop()

	if r.issuesClient != nil {
		r.issuesClient.Close()
	}
	if !results.Load() {
		if r.output != nil {
			r.output.Close()
			os.Remove(r.options.Output)
		}
		gologger.Info().Msgf("No results found. Better luck next time!")
	}

	if r.browser != nil {
		r.browser.Close()
	}
}

// readNewTemplatesFile reads newly added templates from directory if it exists
func (r *Runner) readNewTemplatesFile() ([]string, error) {
	additionsFile := path.Join(r.templatesConfig.TemplatesDirectory, ".new-additions")
	file, err := os.Open(additionsFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	templatesList := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			continue
		}
		templatesList = append(templatesList, text)
	}
	return templatesList, nil
}
