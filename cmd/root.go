// Package cmd implements the worker command for the Kubernetes Job
// that processes GitHub Action logs to create releases and SBOMs.
package cmd

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v69/github"

	// ArangoDB v2 Driver
	"github.com/arangodb/go-driver/v2/arangodb"

	// Import shared packages from the backend
	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/model"
	"github.com/ortelius/pdvd-backend/v12/util"

	"github.com/spf13/cobra"
	"golang.org/x/oauth2"

	// Import SQLite driver for Syft's RPM database scanning if needed
	_ "github.com/glebarez/go-sqlite"
)

var (
	serverURL string
	verbose   bool

	// Global App Credentials (Required for generating installation tokens)
	envAppID      = os.Getenv("GITHUB_APP_ID")
	envPrivateKey = os.Getenv("GITHUB_PRIVATE_KEY")
)

// -------------------- CLI COMMANDS --------------------

var rootCmd = &cobra.Command{
	Use:   "relscanner",
	Short: "Worker for processing GitHub Action workflows via ArangoDB discovery",
}

var workflowCmd = &cobra.Command{
	Use:   "process-workflow",
	Short: "Scan all users in ArangoDB and process their GitHub Action logs",
	RunE:  runScanner,
}

func init() {
	rootCmd.AddCommand(workflowCmd)
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// -------------------- STATE MANAGEMENT --------------------

// ScannerState represents the persisted JSON record in the metadata collection
type ScannerState struct {
	Key            string           `json:"_key,omitempty"`
	ProcessedRepos map[string]int64 `json:"processed_repos"`
}

func loadScannerState(ctx context.Context, dbConn *database.DBConnection) (map[string]int64, error) {
	// Try to fetch the state document
	query := `RETURN DOCUMENT("metadata/relscanner_state")`
	// V2 Driver accepts nil for options if none are needed
	cursor, err := dbConn.Database.Query(ctx, query, nil)
	if err != nil {
		// If collection doesn't exist or query fails, just return empty map (first run)
		log.Printf("      ⚠️  Could not load state (first run?): %v", err)
		return make(map[string]int64), nil
	}
	defer cursor.Close()

	if cursor.HasMore() {
		var state ScannerState
		if _, err := cursor.ReadDocument(ctx, &state); err != nil {
			// If document is null (not found), ReadDocument returns error or we handle nil
			return make(map[string]int64), nil
		}
		if state.ProcessedRepos == nil {
			return make(map[string]int64), nil
		}
		return state.ProcessedRepos, nil
	}

	return make(map[string]int64), nil
}

func saveScannerState(ctx context.Context, dbConn *database.DBConnection, repos map[string]int64) error {
	// Upsert the state document
	query := `
		UPSERT { _key: "relscanner_state" }
		INSERT { _key: "relscanner_state", processed_repos: @repos }
		UPDATE { processed_repos: @repos }
		IN metadata
	`
	bindVars := map[string]interface{}{
		"repos": repos,
	}

	// Use &arangodb.QueryOptions to wrap bindVars for v2 driver
	_, err := dbConn.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: bindVars,
	})
	return err
}

// -------------------- WORKER LOGIC --------------------

func runScanner(_ *cobra.Command, _ []string) error {
	// 1. Configure Server URL
	serverURL = os.Getenv("API_BASE_URL")
	if serverURL == "" {
		serverURL = "http://localhost:3000"
	}
	if verbose {
		log.Printf("Using API Server: %s", serverURL)
	}

	// 2. Validate Required Environment Variables
	var missingVars []string

	if envAppID == "" {
		missingVars = append(missingVars, "GITHUB_APP_ID")
	}
	if envPrivateKey == "" {
		missingVars = append(missingVars, "GITHUB_PRIVATE_KEY")
	}

	if len(missingVars) > 0 {
		return fmt.Errorf("missing required environment variables: %s", strings.Join(missingVars, ", "))
	}

	// 3. Set Default DB Credentials for Local Dev (if missing)
	if _, ok := os.LookupEnv("ARANGO_USER"); !ok {
		os.Setenv("ARANGO_USER", "")
	}
	if _, ok := os.LookupEnv("ARANGO_PASS"); !ok {
		os.Setenv("ARANGO_PASS", "")
	}

	// 4. Connect to ArangoDB
	log.Println("Connecting to ArangoDB...")
	dbConn := database.InitializeDatabase()
	if dbConn.Database == nil {
		return fmt.Errorf("failed to connect to ArangoDB")
	}

	ctx := context.Background()

	// 5. Load State
	log.Println("📥 Loading scanner state from metadata collection...")
	processedRepos, err := loadScannerState(ctx, &dbConn)
	if err != nil {
		log.Printf("⚠️  Error loading state: %v. Starting fresh.", err)
		processedRepos = make(map[string]int64)
	}
	log.Printf("   Loaded state for %d repositories.", len(processedRepos))

	// 6. Find Users with GitHub Installations
	log.Println("🔍 Scanning for users with GitHub connections...")

	query := `
		FOR u IN users 
		FILTER u.github_installation_id != null AND u.github_installation_id != ""
		RETURN u
	`
	cursor, err := dbConn.Database.Query(ctx, query, nil)
	if err != nil {
		return fmt.Errorf("database query failed: %w", err)
	}
	defer cursor.Close()

	userCount := 0
	for cursor.HasMore() {
		var user model.User
		if _, err := cursor.ReadDocument(ctx, &user); err != nil {
			log.Printf("⚠️  Error reading user document: %v", err)
			continue
		}
		userCount++

		log.Printf("👤 Processing user: %s (Install ID: %s)", user.Username, user.GitHubInstallationID)
		if err := processUserInstallation(ctx, user.GitHubInstallationID, user.Username, processedRepos); err != nil {
			log.Printf("❌ Failed to process user %s: %v", user.Username, err)
		}
	}

	// 7. Save State
	log.Println("💾 Saving scanner state...")
	if err := saveScannerState(ctx, &dbConn, processedRepos); err != nil {
		log.Printf("❌ Failed to save state: %v", err)
	} else {
		log.Println("✅ State saved successfully.")
	}

	log.Printf("✅ Scan complete. Processed %d users.", userCount)
	return nil
}

func processUserInstallation(ctx context.Context, installationID, username string, processedRepos map[string]int64) error {
	token, err := getInstallationToken(envAppID, envPrivateKey, installationID)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	opt := &github.ListOptions{PerPage: 100}
	var allRepos []*github.Repository

	for {
		repos, resp, err := client.Apps.ListRepos(ctx, opt)
		if err != nil {
			return fmt.Errorf("failed to list repos: %w", err)
		}
		allRepos = append(allRepos, repos.Repositories...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	log.Printf("   Found %d accessible repositories for %s", len(allRepos), username)

	for _, repo := range allRepos {
		if repo.GetArchived() {
			continue
		}

		owner := repo.GetOwner().GetLogin()
		repoName := repo.GetName()

		log.Printf("   👉 Scanning Repo: %s/%s", owner, repoName)

		if err := processSingleRepo(ctx, client, token, owner, repoName, processedRepos); err != nil {
			log.Printf("      ⚠️  Skipping %s/%s: %v", owner, repoName, err)
		}
	}
	return nil
}

func processSingleRepo(ctx context.Context, client *github.Client, token, owner, repoName string, processedRepos map[string]int64) error {
	// A. Find Latest Relevant Run
	runID, commitSHA, branchName, analysis, err := findLatestRelevantRun(ctx, client, owner, repoName)
	if err != nil {
		return err
	}

	// --- STATE CHECK ---
	repoKey := fmt.Sprintf("%s/%s", owner, repoName)
	lastProcessedID, exists := processedRepos[repoKey]

	if exists && runID <= lastProcessedID {
		log.Printf("      ⏭️  Skipping Run ID %d: Already processed (Last: %d)", runID, lastProcessedID)
		return nil
	}

	log.Printf("      ✅ Found new relevant run: ID %d (Ver: %s, Img: %s)",
		runID, analysis.ReleaseVersion, analysis.DockerImage)

	// B. Determine Basic Version
	releaseVersion := "0.0.0-snapshot"
	if analysis.DockerImage != "" {
		parts := strings.Split(analysis.DockerImage, ":")
		if len(parts) > 1 {
			releaseVersion = parts[len(parts)-1]
		}
		log.Printf("      [Priority] Using Docker Tag from Manifest List: %s", releaseVersion)
	} else if analysis.ReleaseVersion != "" {
		releaseVersion = analysis.ReleaseVersion
	}

	// C. Clone & Extract Git Metadata
	log.Printf("      Cloning repo at %s to extract git metadata...", commitSHA)
	tempDir, err := os.MkdirTemp("", "relscanner-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}

	// --- UPDATED CLEANUP LOGIC ---
	// Defer cleanup of the specific git clone directory AND any stereoscope temps
	defer func() {
		if verbose {
			log.Printf("      Cleaning up temp directory: %s", tempDir)
		}
		os.RemoveAll(tempDir)
		cleanStereoscopeTemps()
	}()

	cloneURL := fmt.Sprintf("https://x-access-token:%s@github.com/%s/%s.git", token, owner, repoName)
	if err := gitCloneCheckout(cloneURL, commitSHA, tempDir); err != nil {
		return fmt.Errorf("failed to clone and checkout: %w", err)
	}

	originalWd, _ := os.Getwd()
	if err := os.Chdir(tempDir); err != nil {
		return fmt.Errorf("failed to chdir to temp repo: %w", err)
	}

	defer func() {
		_ = os.Chdir(originalWd)
	}()

	mapping := util.GetDerivedEnvMapping(make(map[string]string))

	mapping["CompName"] = fmt.Sprintf("%s/%s", owner, repoName)
	mapping["GitRepoProject"] = repoName
	mapping["GitOrg"] = owner
	mapping["GitCommit"] = commitSHA
	mapping["GitBranch"] = branchName
	mapping["BuildId"] = fmt.Sprintf("%d", runID)

	if analysis.DockerImage != "" {
		mapping["DockerRepo"] = analysis.DockerImage
		mapping["DockerTag"] = releaseVersion
		mapping["ProjectType"] = "container"
	} else {
		mapping["GitTag"] = releaseVersion
		mapping["ProjectType"] = "application"
	}

	release := buildRelease(mapping, mapping["ProjectType"])
	populateContentSha(release)

	if release.GitURL == "" {
		release.GitURL = fmt.Sprintf("https://github.com/%s/%s", owner, repoName)
	}
	if verbose {
		fmt.Printf("      Fetching OpenSSF Scorecard for %s @ %s...\n", release.GitURL, release.GitCommit)
	}
	scorecardResult, aggregateScore, err := fetchOpenSSFScorecard(release.GitURL, release.GitCommit)
	if err == nil {
		release.ScorecardResult = scorecardResult
		release.OpenSSFScorecardScore = aggregateScore
		if verbose {
			fmt.Printf("      OpenSSF Score: %.2f/10\n", aggregateScore)
		}
	} else if verbose {
		log.Printf("      Warning: Scorecard fetch failed: %v", err)
	}

	// D. SBOM Acquisition
	var sbomBytes []byte
	var dockerSHA string

	if analysis.HasSBOM {
		log.Println("      ⬇️  Downloading existing SBOM artifact from GitHub...")
		downloaded, err := downloadSBOMArtifact(ctx, client, owner, repoName, runID)
		if err == nil && len(downloaded) > 0 {
			sbomBytes = downloaded
			log.Printf("      ✅ Successfully downloaded SBOM (%d bytes)", len(sbomBytes))
		} else {
			log.Printf("      ⚠️  Failed to download SBOM artifact: %v (falling back to generation)", err)
		}
	}

	if len(sbomBytes) == 0 {
		if analysis.DockerImage != "" {
			if verbose {
				log.Printf("      Generating SBOM from registry image: %s...", analysis.DockerImage)
			}
			sbomBytes, dockerSHA, err = generateSBOMFromInput(ctx, analysis.DockerImage)
			if err != nil {
				return fmt.Errorf("failed to generate SBOM from image: %w", err)
			}
			if verbose && dockerSHA != "" {
				log.Printf("      Extracted Docker SHA: %s", dockerSHA)
			}
		} else {
			log.Println("      ⚠️  No SBOM artifact and no Docker image found. Skipping SBOM generation.")
			return nil
		}
	}

	if dockerSHA != "" {
		release.DockerSha = dockerSHA
		release.ContentSha = dockerSHA
	} else if release.ContentSha == "" {
		release.ContentSha = commitSHA
	}

	sbomObj := model.NewSBOM()
	sbomObj.Content = json.RawMessage(sbomBytes)

	req := model.ReleaseWithSBOM{
		ProjectRelease: *release,
		SBOM:           *sbomObj,
	}

	if err := postRelease(serverURL, req); err != nil {
		return fmt.Errorf("API upload failed: %w", err)
	}
	log.Printf("      🚀 Release %s synced successfully (SHA: %s)", releaseVersion, release.ContentSha)

	// --- UPDATE STATE IN MEMORY ---
	processedRepos[repoKey] = runID

	return nil
}

// -------------------- CLEANUP UTILS --------------------

// cleanStereoscopeTemps finds and removes all /tmp/stereoscope* directories
func cleanStereoscopeTemps() {
	files, err := filepath.Glob("/tmp/stereoscope*")
	if err != nil {
		log.Printf("      ⚠️  Failed to glob stereoscope temps: %v", err)
		return
	}
	for _, f := range files {
		if verbose {
			log.Printf("      Cleaning up stereoscope temp: %s", f)
		}
		if err := os.RemoveAll(f); err != nil {
			log.Printf("      ⚠️  Failed to remove stereoscope temp %s: %v", f, err)
		}
	}
}

// -------------------- AUTO-DISCOVERY --------------------

func findLatestRelevantRun(ctx context.Context, client *github.Client, owner, repo string) (int64, string, string, *LogAnalysis, error) {
	var allRuns []*github.WorkflowRun
	seenRunIDs := make(map[int64]bool)

	targetBranches := []string{"main", "master"}
	targetEvents := []string{"push", "workflow_dispatch", "release"}

	for _, branch := range targetBranches {
		for _, event := range targetEvents {
			opts := &github.ListWorkflowRunsOptions{
				Status:      "success",
				Branch:      branch,
				Event:       event,
				ListOptions: github.ListOptions{PerPage: 100},
			}

			runs, _, err := client.Actions.ListRepositoryWorkflowRuns(ctx, owner, repo, opts)
			if err != nil {
				if verbose {
					log.Printf("      [DEBUG] Failed to fetch runs for branch '%s' event '%s': %v", branch, event, err)
				}
				continue
			}
			if runs.TotalCount != nil && *runs.TotalCount > 0 {
				if verbose {
					log.Printf("      [DEBUG] Found %d runs for branch '%s' event '%s'",
						*runs.TotalCount, branch, event)
				}

				for _, r := range runs.WorkflowRuns {
					if !seenRunIDs[r.GetID()] {
						seenRunIDs[r.GetID()] = true
						allRuns = append(allRuns, r)
					}
				}
			}
		}
	}

	if len(allRuns) == 0 {
		return 0, "", "", nil, fmt.Errorf("no successful runs found on main/master")
	}

	sort.Slice(allRuns, func(i, j int) bool {
		return allRuns[i].GetID() > allRuns[j].GetID()
	})

	for _, run := range allRuns {
		if run.GetID() == 0 {
			continue
		}

		runName := strings.ToLower(run.GetName())
		if strings.Contains(runName, "codeql") ||
			strings.Contains(runName, "analyze") ||
			strings.Contains(runName, "linter") ||
			strings.Contains(runName, "scorecard") {
			continue
		}

		if verbose {
			log.Printf("      Checking Run ID %d (Name: %s, Event: %s, Branch: %s)...",
				run.GetID(), run.GetName(), run.GetEvent(), run.GetHeadBranch())
		}

		analysis, err := fetchAndAnalyzeRun(ctx, client, owner, repo, run.GetID())
		if err != nil {
			continue
		}

		if analysis.DockerImage != "" || analysis.ReleaseVersion != "" {
			return run.GetID(), run.GetHeadSHA(), run.GetHeadBranch(), analysis, nil
		}
	}

	return 0, "", "", nil, fmt.Errorf("no relevant artifacts found in recent runs on main/master")
}

func fetchAndAnalyzeRun(ctx context.Context, client *github.Client, owner, repo string, runID int64) (*LogAnalysis, error) {
	url, resp, err := client.Actions.GetWorkflowRunLogs(ctx, owner, repo, runID, 3)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	logData, err := downloadFile(url.String())
	if err != nil {
		return nil, err
	}

	return parseLogs(logData)
}

func downloadSBOMArtifact(ctx context.Context, client *github.Client, owner, repo string, runID int64) ([]byte, error) {
	opts := &github.ListOptions{PerPage: 100}
	artifacts, _, err := client.Actions.ListWorkflowRunArtifacts(ctx, owner, repo, runID, opts)
	if err != nil {
		return nil, err
	}

	var targetArtifact *github.Artifact
	var availableArtifacts []string

	for _, a := range artifacts.Artifacts {
		name := strings.ToLower(a.GetName())
		availableArtifacts = append(availableArtifacts, a.GetName())

		if strings.Contains(name, "sbom") ||
			strings.Contains(name, "cyclonedx") ||
			strings.Contains(name, "spdx") ||
			strings.Contains(name, "results") {
			targetArtifact = a
			break
		}
	}

	if targetArtifact == nil {
		return nil, fmt.Errorf("no sbom-like artifact found. Available artifacts: [%s]", strings.Join(availableArtifacts, ", "))
	}

	url, _, err := client.Actions.DownloadArtifact(ctx, owner, repo, targetArtifact.GetID(), 10)
	if err != nil {
		return nil, err
	}

	zipBytes, err := downloadFile(url.String())
	if err != nil {
		return nil, err
	}

	r, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return nil, err
	}

	for _, f := range r.File {
		if strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			rc, err := f.Open()
			if err != nil {
				continue
			}
			defer rc.Close()
			return io.ReadAll(rc)
		}
	}

	return nil, fmt.Errorf("no .json file found inside artifact zip")
}

type LogAnalysis struct {
	DockerImage    string
	ReleaseVersion string
	HasSBOM        bool
}

func stripANSI(str string) string {
	const ansi = "[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"
	var re = regexp.MustCompile(ansi)
	return re.ReplaceAllString(str, "")
}

func parseLogs(zipData []byte) (*LogAnalysis, error) {
	r, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, err
	}

	analysis := &LogAnalysis{}
	reManifest := regexp.MustCompile(`(?i).*Created\s+manifest\s+list\s+([^\s]+)`)
	reSBOM := regexp.MustCompile(`(?i)(syft|trivy|cyclonedx|spdx)`)

	for _, f := range r.File {
		if strings.Contains(f.Name, "Set up job") || strings.Contains(f.Name, "Post Run") ||
			strings.Contains(f.Name, "Pre Run") || strings.Contains(f.Name, "Complete job") ||
			strings.Contains(f.Name, "Initialize containers") {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}

		text := string(content)
		scanner := bufio.NewScanner(strings.NewReader(text))
		for scanner.Scan() {
			rawLine := scanner.Text()
			cleanLine := stripANSI(rawLine)
			if strings.Contains(cleanLine, "Z ") {
				parts := strings.SplitN(cleanLine, "Z ", 2)
				if len(parts) == 2 && len(parts[0]) > 10 && strings.Contains(parts[0], "T") && strings.Contains(parts[0], "-") {
					cleanLine = parts[1]
				}
			}
			line := strings.TrimSpace(cleanLine)

			if matches := reManifest.FindStringSubmatch(rawLine); len(matches) > 1 {
				image := strings.TrimSpace(matches[1])
				analysis.DockerImage = image
				parts := strings.Split(image, ":")
				if len(parts) > 1 {
					analysis.ReleaseVersion = parts[len(parts)-1]
				}
				return analysis, nil
			}

			if reSBOM.MatchString(line) {
				analysis.HasSBOM = true
			}
		}
	}
	return analysis, nil
}

// -------------------- IMPORTED FUNCTIONS (releasetracker) --------------------

func buildRelease(mapping map[string]string, projectType string) *model.ProjectRelease {
	release := model.NewProjectRelease()
	release.Name = getOrDefault(mapping["CompName"], mapping["GitRepoProject"], "unknown")
	release.Version = getOrDefault(mapping["DockerTag"], mapping["GitTag"], "0.0.0")
	release.ProjectType = projectType

	release.Basename = mapping["BaseName"]
	release.BuildID = mapping["BuildId"]
	release.BuildNum = mapping["BuildNumber"]
	release.BuildURL = mapping["BuildUrl"]
	release.DockerRepo = mapping["DockerRepo"]
	release.DockerSha = mapping["DockerSha"]
	release.DockerTag = mapping["DockerTag"]
	release.GitBranch = mapping["GitBranch"]
	release.GitBranchCreateCommit = mapping["GitBranchCreateCommit"]
	release.GitBranchParent = mapping["GitBranchParent"]
	release.GitCommit = mapping["GitCommit"]
	release.GitCommitAuthors = mapping["GitCommitAuthors"]
	release.GitCommittersCnt = mapping["GitCommittersCnt"]
	release.GitContribPercentage = mapping["GitContribPercentage"]
	release.GitLinesAdded = mapping["GitLinesAdded"]
	release.GitLinesDeleted = mapping["GitLinesDeleted"]
	release.GitLinesTotal = mapping["GitLinesTotal"]
	release.GitOrg = mapping["GitOrg"]
	release.GitPrevCompCommit = mapping["GitPrevCompCommit"]
	release.GitRepo = mapping["GitRepo"]
	release.GitRepoProject = mapping["GitRepoProject"]
	release.GitSignedOffBy = mapping["GitSignedOffBy"]
	release.GitTag = mapping["GitTag"]
	release.GitTotalCommittersCnt = mapping["GitTotalCommittersCnt"]
	release.GitURL = mapping["GitUrl"]
	release.GitVerifyCommit = mapping["GitVerifyCommit"] == "Y"

	if buildDate := mapping["BuildDate"]; buildDate != "" {
		if t, err := time.Parse(time.RFC3339, buildDate); err == nil {
			release.BuildDate = t
		}
	}
	if gitBranchCreateTimestamp := mapping["GitBranchCreateTimestamp"]; gitBranchCreateTimestamp != "" {
		if t, err := parseGitDate(gitBranchCreateTimestamp); err == nil {
			release.GitBranchCreateTimestamp = t
		}
	}
	if gitCommitTimestamp := mapping["GitCommitTimestamp"]; gitCommitTimestamp != "" {
		if t, err := parseGitDate(gitCommitTimestamp); err == nil {
			release.GitCommitTimestamp = t
		}
	}

	return release
}

func fetchOpenSSFScorecard(gitURL, commitSha string) (*model.ScorecardAPIResponse, float64, error) {
	platform, org, repo, err := parseGitURL(gitURL)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse git URL: %w", err)
	}

	result, aggregateScore, err := getScorecardData(platform, org, repo, commitSha)
	if err == nil {
		return result, aggregateScore, nil
	}

	if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "404") {
		if err := triggerScorecardScan(platform, org, repo); err != nil {
			return nil, 0, fmt.Errorf("failed to trigger scorecard scan: %w", err)
		}

		time.Sleep(5 * time.Second)
		result, aggregateScore, err = getScorecardData(platform, org, repo, commitSha)
		if err == nil {
			return result, aggregateScore, nil
		}
	}
	return nil, 0, err
}

func getScorecardData(platform, org, repo, commitSha string) (*model.ScorecardAPIResponse, float64, error) {
	apiURL := fmt.Sprintf("https://api.securityscorecards.dev/projects/%s/%s/%s", platform, org, repo)
	resp, err := http.Get(apiURL)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, 0, fmt.Errorf("status %d", resp.StatusCode)
	}

	var apiResponse model.ScorecardAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return nil, 0, err
	}
	apiResponse.Repo.Commit = commitSha
	return &apiResponse, apiResponse.Score, nil
}

func triggerScorecardScan(platform, org, repo string) error {
	apiURL := fmt.Sprintf("https://api.securityscorecards.dev/projects/%s/%s/%s", platform, org, repo)
	resp, err := http.Post(apiURL, "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func parseGitURL(gitURL string) (platform, org, repo string, err error) {
	gitURL = strings.TrimSuffix(gitURL, ".git")
	gitURL = strings.TrimPrefix(gitURL, "https://")
	gitURL = strings.TrimPrefix(gitURL, "http://")
	parts := strings.Split(gitURL, "/")
	if len(parts) < 3 {
		return "", "", "", fmt.Errorf("invalid url")
	}
	return parts[0], parts[1], parts[2], nil
}

func parseGitDate(dateStr string) (time.Time, error) {
	formats := []string{
		time.RFC3339,
		time.RFC1123Z,
		"Mon Jan 2 15:04:05 2006 -0700",
		"2006-01-02 15:04:05 -0700",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, dateStr); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unable to parse date: %s", dateStr)
}

func populateContentSha(release *model.ProjectRelease) {
	if release.ProjectType == "docker" || release.ProjectType == "container" {
		if release.DockerSha != "" {
			release.ContentSha = release.DockerSha
		} else if release.GitCommit != "" {
			release.ContentSha = release.GitCommit
		}
	} else {
		if release.GitCommit != "" {
			release.ContentSha = release.GitCommit
		} else if release.DockerSha != "" {
			release.ContentSha = release.DockerSha
		}
	}
}

func getOrDefault(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// -------------------- HELPERS --------------------

func downloadFile(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func generateSBOMFromInput(ctx context.Context, input string) ([]byte, string, error) {
	src, err := syft.GetSource(ctx, input, nil)
	if err != nil {
		return nil, "", err
	}
	s, err := syft.CreateSBOM(ctx, src, nil)
	if err != nil {
		return nil, "", err
	}

	dockerSHA := ""
	if s.Source.Metadata != nil {
		dockerSHA = s.Source.ID
	}

	cfg := cyclonedxjson.DefaultEncoderConfig()
	enc, err := cyclonedxjson.NewFormatEncoderWithConfig(cfg)
	var buf bytes.Buffer
	if err := enc.Encode(&buf, *s); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), dockerSHA, nil
}

func getInstallationToken(appID, pemStr, installID string) (string, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return "", fmt.Errorf("failed to parse private key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	claims := jwt.RegisteredClaims{
		Issuer:    appID,
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(-60 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedJWT, _ := token.SignedString(key)

	api := fmt.Sprintf("https://api.github.com/app/installations/%s/access_tokens", installID)
	req, _ := http.NewRequest("POST", api, nil)
	req.Header.Set("Authorization", "Bearer "+signedJWT)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		return "", fmt.Errorf("github api error: %s", resp.Status)
	}

	var res struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", err
	}
	return res.Token, nil
}

func gitCloneCheckout(repoURL, commitSHA, dest string) error {
	cmd := exec.Command("git", "clone", repoURL, dest)
	if verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("clone failed: %w", err)
	}

	// Use -b <branch> to checkout the SHA as a new temporary branch
	checkoutCmd := exec.Command("git", "-C", dest, "checkout", "-b", "relscanner-checkout", commitSHA)
	if verbose {
		checkoutCmd.Stdout = os.Stdout
		checkoutCmd.Stderr = os.Stderr
	}
	if err := checkoutCmd.Run(); err != nil {
		return fmt.Errorf("checkout sha %s failed: %w", commitSHA, err)
	}
	return nil
}

func postRelease(serverURL string, payload interface{}) error {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal failed: %w", err)
	}

	url := serverURL + "/api/v1/releases"
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("http post failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("server error %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("      API Response: %s", string(body))
	return nil
}
