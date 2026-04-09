// Package cmd implements the worker command for the Kubernetes Job
// that processes GitHub Action logs to create releases and SBOMs.
package cmd

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
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

	// OCI and Container Registry logic
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	// ArangoDB v2 Driver
	"github.com/arangodb/go-driver/v2/arangodb"

	// Import shared packages from the backend
	"github.com/ortelius/ortelius/v12/database"
	"github.com/ortelius/ortelius/v12/model"
	"github.com/ortelius/ortelius/v12/util"

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

// -------------------- NEW DATA STRUCTURES --------------------

// GitDetails represents metadata extracted from OCI image labels
type GitDetails struct {
	Authors  string `json:"authors,omitempty"`
	Licenses string `json:"licenses,omitempty"`
	RefName  string `json:"ref_name,omitempty"`
	Revision string `json:"revision,omitempty"`
	Source   string `json:"source,omitempty"`
	Title    string `json:"title,omitempty"`
	URL      string `json:"url,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	Version  string `json:"version,omitempty"`
}

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

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// -------------------- STATE MANAGEMENT --------------------

type ScannerState struct {
	Key            string           `json:"_key,omitempty"`
	ProcessedRepos map[string]int64 `json:"processed_repos"`
}

func loadScannerState(ctx context.Context, dbConn *database.DBConnection) (map[string]int64, error) {
	query := `RETURN DOCUMENT("metadata/relscanner_state")`
	cursor, err := dbConn.Database.Query(ctx, query, nil)
	if err != nil {
		log.Printf("      ⚠️  Could not load state (first run?): %v", err)
		return make(map[string]int64), nil
	}
	defer cursor.Close()

	if cursor.HasMore() {
		var state ScannerState
		if _, err := cursor.ReadDocument(ctx, &state); err != nil {
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
	query := `
		UPSERT { _key: "relscanner_state" }
		INSERT { _key: "relscanner_state", processed_repos: @repos }
		UPDATE { processed_repos: @repos }
		IN metadata
	`
	bindVars := map[string]interface{}{"repos": repos}
	_, err := dbConn.Database.Query(ctx, query, &arangodb.QueryOptions{BindVars: bindVars})
	return err
}

// -------------------- WORKER LOGIC --------------------

func runScanner(_ *cobra.Command, _ []string) error {
	serverURL = os.Getenv("API_BASE_URL")
	if serverURL == "" {
		serverURL = "http://localhost:3000"
	}

	if envAppID == "" || envPrivateKey == "" {
		return fmt.Errorf("missing GITHUB_APP_ID or GITHUB_PRIVATE_KEY")
	}

	log.Println("Connecting to ArangoDB...")
	dbConn := database.InitializeDatabase()
	if dbConn.Database == nil {
		return fmt.Errorf("failed to connect to ArangoDB")
	}

	ctx := context.Background()
	processedRepos, err := loadScannerState(ctx, &dbConn)
	if err != nil {
		processedRepos = make(map[string]int64)
	}

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

	for cursor.HasMore() {
		var user model.User
		if _, err := cursor.ReadDocument(ctx, &user); err == nil {
			processUserInstallation(ctx, user.GitHubInstallationID, user.Username, processedRepos)
		}
	}

	saveScannerState(ctx, &dbConn, processedRepos)
	return nil
}

func processUserInstallation(ctx context.Context, installationID, _ string, processedRepos map[string]int64) error {
	token, err := getInstallationToken(envAppID, envPrivateKey, installationID)
	if err != nil {
		return err
	}

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	opt := &github.ListOptions{PerPage: 100}
	for {
		repos, resp, err := client.Apps.ListRepos(ctx, opt)
		if err != nil {
			break
		}
		for _, repo := range repos.Repositories {
			if !repo.GetArchived() {
				processSingleRepo(ctx, client, token, repo.GetOwner().GetLogin(), repo.GetName(), processedRepos)
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return nil
}

func processSingleRepo(ctx context.Context, client *github.Client, token, owner, repoName string, processedRepos map[string]int64) error {
	runID, commitSHA, branchName, analysis, err := findLatestRelevantRun(ctx, client, owner, repoName)
	if err != nil {
		return err
	}

	repoKey := fmt.Sprintf("%s/%s", owner, repoName)
	if lastID, exists := processedRepos[repoKey]; exists && runID <= lastID {
		return nil
	}

	// 1. EXTRACT OCI LABELS (Refined Git Info from Image)
	var gitDetails *GitDetails
	if analysis.DockerImage != "" {
		gitDetails, _ = extractImageLabels(analysis.DockerImage)
	}

	// Determine Version
	releaseVersion := "0.0.0-snapshot"
	if analysis.DockerImage != "" {
		parts := strings.Split(analysis.DockerImage, ":")
		if len(parts) > 1 {
			releaseVersion = parts[len(parts)-1]
		}
	} else if analysis.ReleaseVersion != "" {
		releaseVersion = analysis.ReleaseVersion
	}

	// 2. CLONE & DERIVE MAPPING
	tempDir, _ := os.MkdirTemp("", "relscanner-*")
	defer func() {
		os.RemoveAll(tempDir)
		cleanStereoscopeTemps()
	}()

	cloneURL := fmt.Sprintf("https://x-access-token:%s@github.com/%s/%s.git", token, owner, repoName)
	if err := gitCloneCheckout(cloneURL, commitSHA, tempDir); err != nil {
		return err
	}

	originalWd, _ := os.Getwd()
	os.Chdir(tempDir)
	defer os.Chdir(originalWd)

	mapping := util.GetDerivedEnvMapping(make(map[string]string))
	mapping["CompName"] = fmt.Sprintf("%s/%s", owner, repoName)
	mapping["GitRepoProject"] = repoName
	mapping["GitOrg"] = owner
	mapping["GitCommit"] = commitSHA
	mapping["GitBranch"] = branchName
	mapping["BuildId"] = fmt.Sprintf("%d", runID)

	// Apply priorities from OCI labels if found
	if gitDetails != nil {
		if gitDetails.URL != "" {
			mapping["GitUrl"] = gitDetails.URL
		}
		if gitDetails.Revision != "" {
			mapping["GitCommit"] = gitDetails.Revision
		}
		if gitDetails.Authors != "" {
			mapping["GitCommitAuthors"] = gitDetails.Authors
		}
	}

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

	// 3. SBOM ACQUISITION (OCI Attestation Priority)
	var sbomBytes []byte
	var dockerSHA string

	if analysis.DockerImage != "" {
		log.Printf("      🔍 Checking OCI Referrers for SBOM: %s", analysis.DockerImage)
		extractedSbom, err := extractSBOMFromImage(analysis.DockerImage)
		if err == nil {
			sbomBytes = extractedSbom
			log.Printf("      ✅ Extracted SBOM from OCI Attestation")
		}
	}

	if len(sbomBytes) == 0 && analysis.HasSBOM {
		downloaded, err := downloadSBOMArtifact(ctx, client, owner, repoName, runID)
		if err == nil {
			sbomBytes = downloaded
		}
	}

	if len(sbomBytes) == 0 && analysis.DockerImage != "" {
		sbomBytes, dockerSHA, _ = generateSBOMFromInput(ctx, analysis.DockerImage)
	}

	if dockerSHA != "" {
		release.DockerSha = dockerSHA
		release.ContentSha = dockerSHA
	}

	// 4. SCORECARD & UPLOAD
	scorecardResult, aggregateScore, err := fetchOpenSSFScorecard(release.GitURL, release.GitCommit)
	if err == nil {
		release.ScorecardResult = scorecardResult
		release.OpenSSFScorecardScore = aggregateScore
	}

	sbomObj := model.NewSBOM()
	sbomObj.Content = json.RawMessage(sbomBytes)
	req := model.ReleaseWithSBOM{ProjectRelease: *release, SBOM: *sbomObj}

	if err := postRelease(serverURL, req); err == nil {
		processedRepos[repoKey] = runID
		log.Printf("      🚀 Release %s synced (SHA: %s)", releaseVersion, release.ContentSha)
	}

	return nil
}

// -------------------- NEW OCI & SBOM LOGIC --------------------

func extractImageLabels(imageRef string) (*GitDetails, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, err
	}
	desc, err := remote.Get(ref)
	if err != nil {
		return nil, err
	}
	img, err := desc.Image()
	if err != nil {
		return nil, err
	}
	configFile, err := img.ConfigFile()
	if err != nil {
		return nil, err
	}

	labels := configFile.Config.Labels
	return &GitDetails{
		Authors:  labels["org.opencontainers.image.authors"],
		Licenses: labels["org.opencontainers.image.licenses"],
		Revision: labels["org.opencontainers.image.revision"],
		Source:   labels["org.opencontainers.image.source"],
		URL:      labels["org.opencontainers.image.url"],
		Version:  labels["org.opencontainers.image.version"],
	}, nil
}

func extractSBOMFromImage(imageRef string) ([]byte, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, err
	}

	// Try OCI Referrers API first
	if sbom, err := extractSBOMFromOCIReferrers(ref); err == nil {
		return sbom, nil
	}

	// Resolve to digest for attachment/attestation lookup
	desc, err := remote.Get(ref)
	if err != nil {
		return nil, err
	}
	leafRef, _ := name.ParseReference(fmt.Sprintf("%s@%s", ref.Context().Name(), desc.Digest.String()))

	if sbom, err := extractSBOMFromCosignAttestation(leafRef); err == nil {
		return sbom, nil
	}
	return nil, fmt.Errorf("no OCI SBOM found")
}

func extractSBOMFromOCIReferrers(ref name.Reference) ([]byte, error) {
	desc, err := remote.Get(ref)
	if err != nil {
		return nil, err
	}
	idx, err := remote.Referrers(ref.Context().Digest(desc.Digest.String()))
	if err != nil {
		return nil, err
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}

	for _, m := range manifest.Manifests {
		aType := strings.ToLower(m.ArtifactType)
		if aType == "" {
			aType = strings.ToLower(string(m.MediaType))
		}
		if strings.Contains(aType, "sbom") || strings.Contains(aType, "cyclonedx") {
			rDigest, _ := name.NewDigest(fmt.Sprintf("%s@%s", ref.Context().Name(), m.Digest.String()))
			img, err := remote.Image(rDigest)
			if err != nil {
				continue
			}
			layers, _ := img.Layers()
			if len(layers) > 0 {
				rc, _ := layers[0].Uncompressed()
				defer rc.Close()
				return io.ReadAll(rc)
			}
		}
	}
	return nil, fmt.Errorf("not found")
}

func extractSBOMFromCosignAttestation(ref name.Reference) ([]byte, error) {
	desc, err := remote.Get(ref)
	if err != nil {
		return nil, err
	}
	idx, err := remote.Referrers(ref.Context().Digest(desc.Digest.String()))
	if err != nil {
		return nil, err
	}
	manifest, _ := idx.IndexManifest()

	for _, m := range manifest.Manifests {
		if !strings.Contains(string(m.MediaType), "dsse") {
			continue
		}
		rDigest, _ := name.NewDigest(fmt.Sprintf("%s@%s", ref.Context().Name(), m.Digest.String()))
		img, _ := remote.Image(rDigest)
		layers, _ := img.Layers()
		if len(layers) > 0 {
			rc, _ := layers[0].Uncompressed()
			content, _ := io.ReadAll(rc)
			rc.Close()

			var env struct {
				Payload string `json:"payload"`
			}
			if err := json.Unmarshal(content, &env); err == nil {
				data, _ := base64.StdEncoding.DecodeString(env.Payload)
				var statement map[string]interface{}
				if err := json.Unmarshal(data, &statement); err == nil {
					if pred, ok := statement["predicate"]; ok {
						return json.Marshal(pred)
					}
				}
			}
		}
	}
	return nil, fmt.Errorf("not found")
}

// -------------------- EXISTING HELPERS --------------------

func cleanStereoscopeTemps() {
	files, _ := filepath.Glob("/tmp/stereoscope*")
	for _, f := range files {
		os.RemoveAll(f)
	}
}

func findLatestRelevantRun(ctx context.Context, client *github.Client, owner, repo string) (int64, string, string, *LogAnalysis, error) {
	var allRuns []*github.WorkflowRun
	seenRunIDs := make(map[int64]bool)
	targetBranches := []string{"main", "master"}
	targetEvents := []string{"push", "workflow_dispatch", "release"}

	for _, branch := range targetBranches {
		for _, event := range targetEvents {
			opts := &github.ListWorkflowRunsOptions{
				Status: "success", Branch: branch, Event: event, ListOptions: github.ListOptions{PerPage: 100},
			}
			runs, _, err := client.Actions.ListRepositoryWorkflowRuns(ctx, owner, repo, opts)
			if err == nil && runs.TotalCount != nil && *runs.TotalCount > 0 {
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
		return 0, "", "", nil, fmt.Errorf("no successful runs")
	}

	sort.Slice(allRuns, func(i, j int) bool { return allRuns[i].GetID() > allRuns[j].GetID() })

	for _, run := range allRuns {
		analysis, err := fetchAndAnalyzeRun(ctx, client, owner, repo, run.GetID())
		if err == nil && (analysis.DockerImage != "" || analysis.ReleaseVersion != "") {
			return run.GetID(), run.GetHeadSHA(), run.GetHeadBranch(), analysis, nil
		}
	}
	return 0, "", "", nil, fmt.Errorf("no artifacts found")
}

func fetchAndAnalyzeRun(ctx context.Context, client *github.Client, owner, repo string, runID int64) (*LogAnalysis, error) {
	url, resp, err := client.Actions.GetWorkflowRunLogs(ctx, owner, repo, runID, 3)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	logData, _ := downloadFile(url.String())
	return parseLogs(logData)
}

func downloadSBOMArtifact(ctx context.Context, client *github.Client, owner, repo string, runID int64) ([]byte, error) {
	artifacts, _, err := client.Actions.ListWorkflowRunArtifacts(ctx, owner, repo, runID, &github.ListOptions{PerPage: 100})
	if err != nil {
		return nil, err
	}

	var target *github.Artifact
	for _, a := range artifacts.Artifacts {
		n := strings.ToLower(a.GetName())
		if strings.Contains(n, "sbom") || strings.Contains(n, "cyclonedx") {
			target = a
			break
		}
	}
	if target == nil {
		return nil, fmt.Errorf("no sbom artifact")
	}

	url, _, _ := client.Actions.DownloadArtifact(ctx, owner, repo, target.GetID(), 10)
	zipBytes, _ := downloadFile(url.String())
	r, _ := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	for _, f := range r.File {
		if strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			rc, _ := f.Open()
			defer rc.Close()
			return io.ReadAll(rc)
		}
	}
	return nil, fmt.Errorf("no json")
}

type LogAnalysis struct {
	DockerImage    string
	ReleaseVersion string
	HasSBOM        bool
}

func stripANSI(str string) string {
	const ansi = "[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"
	return regexp.MustCompile(ansi).ReplaceAllString(str, "")
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
		rc, _ := f.Open()
		content, _ := io.ReadAll(rc)
		rc.Close()
		scanner := bufio.NewScanner(strings.NewReader(string(content)))
		for scanner.Scan() {
			line := stripANSI(scanner.Text())
			if matches := reManifest.FindStringSubmatch(line); len(matches) > 1 {
				image := strings.TrimSpace(matches[1])
				analysis.DockerImage = image
				parts := strings.Split(image, ":")
				if len(parts) > 1 {
					analysis.ReleaseVersion = parts[len(parts)-1]
				}
			}
			if reSBOM.MatchString(line) {
				analysis.HasSBOM = true
			}
		}
	}
	return analysis, nil
}

func buildRelease(mapping map[string]string, projectType string) *model.ProjectRelease {
	release := model.NewProjectRelease()
	release.Name = getOrDefault(mapping["CompName"], mapping["GitRepoProject"], "unknown")
	release.Version = getOrDefault(mapping["DockerTag"], mapping["GitTag"], "0.0.0")
	release.ProjectType = projectType
	release.DockerRepo = mapping["DockerRepo"]
	release.DockerTag = mapping["DockerTag"]
	release.GitBranch = mapping["GitBranch"]
	release.GitCommit = mapping["GitCommit"]
	release.GitOrg = mapping["GitOrg"]
	release.GitURL = mapping["GitUrl"]
	return release
}

func fetchOpenSSFScorecard(gitURL, commitSha string) (*model.ScorecardAPIResponse, float64, error) {
	platform, org, repo, err := parseGitURL(gitURL)
	if err != nil {
		return nil, 0, err
	}
	apiURL := fmt.Sprintf("https://api.securityscorecards.dev/projects/%s/%s/%s", platform, org, repo)
	resp, err := http.Get(apiURL)
	if err != nil || resp.StatusCode != 200 {
		return nil, 0, fmt.Errorf("not found")
	}
	var res model.ScorecardAPIResponse
	json.NewDecoder(resp.Body).Decode(&res)
	res.Repo.Commit = commitSha
	return &res, res.Score, nil
}

func parseGitURL(gitURL string) (p, o, r string, err error) {
	gitURL = strings.TrimPrefix(strings.TrimSuffix(gitURL, ".git"), "https://")
	parts := strings.Split(gitURL, "/")
	if len(parts) < 3 {
		return "", "", "", fmt.Errorf("invalid")
	}
	return parts[0], parts[1], parts[2], nil
}

func populateContentSha(release *model.ProjectRelease) {
	if (release.ProjectType == "docker" || release.ProjectType == "container") && release.DockerSha != "" {
		release.ContentSha = release.DockerSha
	} else {
		release.ContentSha = release.GitCommit
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
	var buf bytes.Buffer
	enc, _ := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	enc.Encode(&buf, *s)
	return buf.Bytes(), dockerSHA, nil
}

func getInstallationToken(appID, pemStr, installID string) (string, error) {
	block, _ := pem.Decode([]byte(pemStr))
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	claims := jwt.RegisteredClaims{
		Issuer: appID, IssuedAt: jwt.NewNumericDate(time.Now().Add(-60 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedJWT, _ := token.SignedString(key)
	api := fmt.Sprintf("https://api.github.com/app/installations/%s/access_tokens", installID)
	req, _ := http.NewRequest("POST", api, nil)
	req.Header.Set("Authorization", "Bearer "+signedJWT)
	resp, _ := http.DefaultClient.Do(req)
	var res struct {
		Token string `json:"token"`
	}
	json.NewDecoder(resp.Body).Decode(&res)
	return res.Token, nil
}

func gitCloneCheckout(repoURL, commitSHA, dest string) error {
	exec.Command("git", "clone", repoURL, dest).Run()
	return exec.Command("git", "-C", dest, "checkout", "-b", "relscanner-checkout", commitSHA).Run()
}

func postRelease(serverURL string, payload interface{}) error {
	jsonData, _ := json.Marshal(payload)
	resp, err := http.Post(serverURL+"/api/v1/releases", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	if resp.StatusCode != 201 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}
