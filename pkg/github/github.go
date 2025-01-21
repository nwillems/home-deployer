package github

// IMPORTED From,
//  https://github.com/go-playground/webhooks/blob/e24c5f0745d575a963d97fbc0fdbae521369e6fb/github/github.go

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"slices"
	"strings"
)

// parse errors
var (
	ErrEventNotSpecifiedToParse  = errors.New("no Event specified to parse")
	ErrInvalidHTTPMethod         = errors.New("invalid HTTP Method")
	ErrMissingGithubEventHeader  = errors.New("missing X-GitHub-Event Header")
	ErrMissingHubSignatureHeader = errors.New("missing X-Hub-Signature-256 Header")
	ErrEventNotFound             = errors.New("event not defined to be parsed")
	ErrParsingPayload            = errors.New("error parsing payload")
	ErrHMACVerificationFailed    = errors.New("HMAC verification failed")
)

// Event defines a GitHub hook event type
type Event string

// GitHub hook types
const (
	CheckRunEvent                            Event = "check_run"
	CheckSuiteEvent                          Event = "check_suite"
	CommitCommentEvent                       Event = "commit_comment"
	CreateEvent                              Event = "create"
	DeleteEvent                              Event = "delete"
	DependabotAlertEvent                     Event = "dependabot_alert"
	DeployKeyEvent                           Event = "deploy_key"
	DeploymentEvent                          Event = "deployment"
	DeploymentStatusEvent                    Event = "deployment_status"
	ForkEvent                                Event = "fork"
	GollumEvent                              Event = "gollum"
	InstallationEvent                        Event = "installation"
	InstallationRepositoriesEvent            Event = "installation_repositories"
	IntegrationInstallationEvent             Event = "integration_installation"
	IntegrationInstallationRepositoriesEvent Event = "integration_installation_repositories"
	IssueCommentEvent                        Event = "issue_comment"
	IssuesEvent                              Event = "issues"
	LabelEvent                               Event = "label"
	MemberEvent                              Event = "member"
	MembershipEvent                          Event = "membership"
	MilestoneEvent                           Event = "milestone"
	MetaEvent                                Event = "meta"
	OrganizationEvent                        Event = "organization"
	OrgBlockEvent                            Event = "org_block"
	PageBuildEvent                           Event = "page_build"
	PingEvent                                Event = "ping"
	ProjectCardEvent                         Event = "project_card"
	ProjectColumnEvent                       Event = "project_column"
	ProjectEvent                             Event = "project"
	PublicEvent                              Event = "public"
	PullRequestEvent                         Event = "pull_request"
	PullRequestReviewEvent                   Event = "pull_request_review"
	PullRequestReviewCommentEvent            Event = "pull_request_review_comment"
	PushEvent                                Event = "push"
	ReleaseEvent                             Event = "release"
	RepositoryEvent                          Event = "repository"
	RepositoryVulnerabilityAlertEvent        Event = "repository_vulnerability_alert"
	SecurityAdvisoryEvent                    Event = "security_advisory"
	StatusEvent                              Event = "status"
	TeamEvent                                Event = "team"
	TeamAddEvent                             Event = "team_add"
	WatchEvent                               Event = "watch"
	WorkflowDispatchEvent                    Event = "workflow_dispatch"
	WorkflowJobEvent                         Event = "workflow_job"
	WorkflowRunEvent                         Event = "workflow_run"
	GitHubAppAuthorizationEvent              Event = "github_app_authorization"
	CodeScanningAlertEvent                   Event = "code_scanning_alert"
)

// EventSubtype defines a GitHub Hook Event subtype
type EventSubtype string

// GitHub hook event subtypes
const (
	NoSubtype     EventSubtype = ""
	BranchSubtype EventSubtype = "branch"
	TagSubtype    EventSubtype = "tag"
	PullSubtype   EventSubtype = "pull"
	IssueSubtype  EventSubtype = "issues"
)

type Handlers struct {
	// CheckRunEvent
	CheckRunEvent [](chan CheckRunPayload)
	// CheckSuiteEvent
	CheckSuiteEvent [](chan CheckSuitePayload)
	// CommitCommentEvent
	CommitCommentEvent [](chan CommitCommentPayload)
	// CreateEvent
	CreateEvent [](chan CreatePayload)
	// DeleteEvent
	DeleteEvent [](chan DeletePayload)
	// DependabotAlertEvent
	DependabotAlertEvent [](chan DependabotAlertPayload)
	// DeployKeyEvent
	DeployKeyEvent [](chan DeployKeyPayload)
	// DeploymentEvent
	DeploymentEvent [](chan DeploymentPayload)
	// DeploymentStatusEvent
	DeploymentStatusEvent [](chan DeploymentStatusPayload)
	// ForkEvent
	ForkEvent [](chan ForkPayload)
	// GollumEvent
	GollumEvent [](chan GollumPayload)
	// InstallationEvent
	InstallationEvent [](chan InstallationPayload)
	// InstallationRepositoriesEvent
	InstallationRepositoriesEvent [](chan InstallationRepositoriesPayload)
	// IntegrationInstallationEvent
	IntegrationInstallationEvent [](chan IntegrationInstallationPayload)
	// IntegrationInstallationRepositoriesEvent
	IntegrationInstallationRepositoriesEvent [](chan IntegrationInstallationRepositoriesPayload)
	// IssueCommentEvent
	IssueCommentEvent [](chan IssueCommentPayload)
	// IssuesEvent
	IssuesEvent [](chan IssuesPayload)
	// LabelEvent
	LabelEvent [](chan LabelPayload)
	// MemberEvent
	MemberEvent [](chan MemberPayload)
	// MembershipEvent
	MembershipEvent [](chan MembershipPayload)
	// MetaEvent
	MetaEvent [](chan MetaPayload)
	// MilestoneEvent
	MilestoneEvent [](chan MilestonePayload)
	// OrganizationEvent
	OrganizationEvent [](chan OrganizationPayload)
	// OrgBlockEvent
	OrgBlockEvent [](chan OrgBlockPayload)
	// PageBuildEvent
	PageBuildEvent [](chan PageBuildPayload)
	// PingEvent
	PingEvent [](chan PingPayload)
	// ProjectCardEvent
	ProjectCardEvent [](chan ProjectCardPayload)
	// ProjectColumnEvent
	ProjectColumnEvent [](chan ProjectColumnPayload)
	// ProjectEvent
	ProjectEvent [](chan ProjectPayload)
	// PublicEvent
	PublicEvent [](chan PublicPayload)
	// PullRequestEvent
	PullRequestEvent [](chan PullRequestPayload)
	// PullRequestReviewEvent
	PullRequestReviewEvent [](chan PullRequestReviewPayload)
	// PullRequestReviewCommentEvent
	PullRequestReviewCommentEvent [](chan PullRequestReviewCommentPayload)
	// PushEvent
	PushEvent [](chan PushPayload)
	// ReleaseEvent
	ReleaseEvent [](chan ReleasePayload)
	// RepositoryEvent
	RepositoryEvent [](chan RepositoryPayload)
	// RepositoryVulnerabilityAlertEvent
	RepositoryVulnerabilityAlertEvent [](chan RepositoryVulnerabilityAlertPayload)
	// SecurityAdvisoryEvent
	SecurityAdvisoryEvent [](chan SecurityAdvisoryPayload)
	// StatusEvent
	StatusEvent [](chan StatusPayload)
	// TeamEvent
	TeamEvent [](chan TeamPayload)
	// TeamAddEvent
	TeamAddEvent [](chan TeamAddPayload)
	// WatchEvent
	WatchEvent [](chan WatchPayload)
	// WorkflowDispatchEvent
	WorkflowDispatchEvent [](chan WorkflowDispatchPayload)
	// WorkflowJobEvent
	WorkflowJobEvent [](chan WorkflowJobPayload)
	// WorkflowRunEvent
	WorkflowRunEvent [](chan WorkflowRunPayload)
	// GitHubAppAuthorizationEvent
	GitHubAppAuthorizationEvent [](chan GitHubAppAuthorizationPayload)
	// CodeScanningAlertEvent
	CodeScanningAlertEvent [](chan CodeScanningAlertPayload)
}

// Webhook instance contains all methods needed to process events
type Webhook struct {
	secret   string
	handlers Handlers
}

// New creates and returns a WebHook instance denoted by the Provider type
func New(secret string) (*Webhook, error) {
	if len(secret) == 0 {
		return nil, errors.New("secret cannot be empty")
	}

	hook := new(Webhook)
	hook.secret = secret
	hook.handlers = Handlers{}

	return hook, nil
}

func onEvent[T any](fn chan T, event *[](chan T)) {
	if event == nil {
		*event = make([](chan T), 0)
	}

	*event = append(*event, fn)
}

// OnCheckRun registers a function to handle CheckRunEvent events
func (hook *Webhook) OnCheckRun(fn chan CheckRunPayload) {
	onEvent(fn, &hook.handlers.CheckRunEvent)
}

func (hook *Webhook) OnCheckSuite(fn chan CheckSuitePayload) {
	onEvent(fn, &hook.handlers.CheckSuiteEvent)
}

func (hook *Webhook) OnCommitComment(fn chan CommitCommentPayload) {
	onEvent(fn, &hook.handlers.CommitCommentEvent)
}

func (hook *Webhook) OnCreate(fn chan CreatePayload) {
	onEvent(fn, &hook.handlers.CreateEvent)
}

func (hook *Webhook) OnDelete(fn chan DeletePayload) {
	onEvent(fn, &hook.handlers.DeleteEvent)
}

func (hook *Webhook) OnDependabotAlert(fn chan DependabotAlertPayload) {
	onEvent(fn, &hook.handlers.DependabotAlertEvent)
}

func (hook *Webhook) OnDeployKey(fn chan DeployKeyPayload) {
	onEvent(fn, &hook.handlers.DeployKeyEvent)
}

func (hook *Webhook) OnDeployment(fn chan DeploymentPayload) {
	onEvent(fn, &hook.handlers.DeploymentEvent)
}

func (hook *Webhook) OnDeploymentStatus(fn chan DeploymentStatusPayload) {
	onEvent(fn, &hook.handlers.DeploymentStatusEvent)
}

func (hook *Webhook) OnFork(fn chan ForkPayload) {
	onEvent(fn, &hook.handlers.ForkEvent)
}

func (hook *Webhook) OnGollum(fn chan GollumPayload) {
	onEvent(fn, &hook.handlers.GollumEvent)
}

func (hook *Webhook) OnInstallation(fn chan InstallationPayload) {
	onEvent(fn, &hook.handlers.InstallationEvent)
}

func (hook *Webhook) OnInstallationRepositories(fn chan InstallationRepositoriesPayload) {
	onEvent(fn, &hook.handlers.InstallationRepositoriesEvent)
}

func (hook *Webhook) OnIntegrationInstallation(fn chan IntegrationInstallationPayload) {
	onEvent(fn, &hook.handlers.IntegrationInstallationEvent)
}

func (hook *Webhook) OnIntegrationInstallationRepositories(fn chan IntegrationInstallationRepositoriesPayload) {
	onEvent(fn, &hook.handlers.IntegrationInstallationRepositoriesEvent)
}

func (hook *Webhook) OnIssueComment(fn chan IssueCommentPayload) {
	onEvent(fn, &hook.handlers.IssueCommentEvent)
}

func (hook *Webhook) OnIssues(fn chan IssuesPayload) {
	onEvent(fn, &hook.handlers.IssuesEvent)
}

func (hook *Webhook) OnLabel(fn chan LabelPayload) {
	onEvent(fn, &hook.handlers.LabelEvent)
}

func (hook *Webhook) OnMember(fn chan MemberPayload) {
	onEvent(fn, &hook.handlers.MemberEvent)
}

func (hook *Webhook) OnMembership(fn chan MembershipPayload) {
	onEvent(fn, &hook.handlers.MembershipEvent)
}

func (hook *Webhook) OnMilestone(fn chan MilestonePayload) {
	onEvent(fn, &hook.handlers.MilestoneEvent)
}

func (hook *Webhook) OnMeta(fn chan MetaPayload) {
	onEvent(fn, &hook.handlers.MetaEvent)
}

func (hook *Webhook) OnOrganization(fn chan OrganizationPayload) {
	onEvent(fn, &hook.handlers.OrganizationEvent)
}

func (hook *Webhook) OnOrgBlock(fn chan OrgBlockPayload) {
	onEvent(fn, &hook.handlers.OrgBlockEvent)
}

func (hook *Webhook) OnPageBuild(fn chan PageBuildPayload) {
	onEvent(fn, &hook.handlers.PageBuildEvent)
}

func (hook *Webhook) OnPing(fn chan PingPayload) {
	onEvent(fn, &hook.handlers.PingEvent)
}

func (hook *Webhook) OnProjectCard(fn chan ProjectCardPayload) {
	onEvent(fn, &hook.handlers.ProjectCardEvent)
}

func (hook *Webhook) OnProjectColumn(fn chan ProjectColumnPayload) {
	onEvent(fn, &hook.handlers.ProjectColumnEvent)
}

func (hook *Webhook) OnProject(fn chan ProjectPayload) {
	onEvent(fn, &hook.handlers.ProjectEvent)
}

func (hook *Webhook) OnPublic(fn chan PublicPayload) {
	onEvent(fn, &hook.handlers.PublicEvent)
}

func (hook *Webhook) OnPullRequest(fn chan PullRequestPayload) {
	onEvent(fn, &hook.handlers.PullRequestEvent)
}

func (hook *Webhook) OnPullRequestReview(fn chan PullRequestReviewPayload) {
	onEvent(fn, &hook.handlers.PullRequestReviewEvent)
}

func (hook *Webhook) OnPullRequestReviewComment(fn chan PullRequestReviewCommentPayload) {
	onEvent(fn, &hook.handlers.PullRequestReviewCommentEvent)
}

func (hook *Webhook) OnPush(fn chan PushPayload) {
	onEvent(fn, &hook.handlers.PushEvent)
}

func (hook *Webhook) OnRelease(fn chan ReleasePayload) {
	onEvent(fn, &hook.handlers.ReleaseEvent)
}

func (hook *Webhook) OnRepository(fn chan RepositoryPayload) {
	onEvent(fn, &hook.handlers.RepositoryEvent)
}

func (hook *Webhook) OnRepositoryVulnerabilityAlert(fn chan RepositoryVulnerabilityAlertPayload) {
	onEvent(fn, &hook.handlers.RepositoryVulnerabilityAlertEvent)
}

func (hook *Webhook) OnSecurityAdvisory(fn chan SecurityAdvisoryPayload) {
	onEvent(fn, &hook.handlers.SecurityAdvisoryEvent)
}

func (hook *Webhook) OnStatus(fn chan StatusPayload) {
	onEvent(fn, &hook.handlers.StatusEvent)
}

func (hook *Webhook) OnTeam(fn chan TeamPayload) {
	onEvent(fn, &hook.handlers.TeamEvent)
}

func (hook *Webhook) OnTeamAdd(fn chan TeamAddPayload) {
	onEvent(fn, &hook.handlers.TeamAddEvent)
}

func (hook *Webhook) OnWatch(fn chan WatchPayload) {
	onEvent(fn, &hook.handlers.WatchEvent)
}

func (hook *Webhook) OnWorkflowDispatch(fn chan WorkflowDispatchPayload) {
	onEvent(fn, &hook.handlers.WorkflowDispatchEvent)
}

func (hook *Webhook) OnWorkflowJob(fn chan WorkflowJobPayload) {
	onEvent(fn, &hook.handlers.WorkflowJobEvent)
}

func (hook *Webhook) OnWorkflowRun(fn chan WorkflowRunPayload) {
	onEvent(fn, &hook.handlers.WorkflowRunEvent)
}

func (hook *Webhook) OnGitHubAppAuthorization(fn chan GitHubAppAuthorizationPayload) {
	onEvent(fn, &hook.handlers.GitHubAppAuthorizationEvent)
}

func (hook *Webhook) OnCodeScanningAlert(fn chan CodeScanningAlertPayload) {
	onEvent(fn, &hook.handlers.CodeScanningAlertEvent)
}

func GenericHandle[T any](payload []byte, hs [](chan T)) error {
	var pl T
	err := json.Unmarshal(payload, &pl)
	if err != nil {
		return err
	}

	for _, h := range hs {
		h <- pl
	}

	return nil
}

func (hook *Webhook) Handle(events ...Event) (http.HandlerFunc, error) {
	if len(events) == 0 {
		return nil, ErrEventNotSpecifiedToParse
	}

	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received request from %s", r.RemoteAddr)
		defer func() {
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
		}()

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte("Method Not Allowed"))
			return
		}

		event := r.Header.Get("X-GitHub-Event")
		if event == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Missing X-GitHub-Event Header"))
			return
		}

		log.Printf("Received request with event %s", event)

		gitHubEvent := Event(event)
		found := slices.Contains(events, gitHubEvent)
		// event not defined to be parsed
		if !found {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Event Not Defined"))
			return
		}

		payload, err := io.ReadAll(r.Body)
		if err != nil || len(payload) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// If we have a Secret set, we should check the MAC
		signature := r.Header.Get("X-Hub-Signature-256")
		if len(signature) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Missing X-Hub-Signature-256 Header"))
			return
		}

		signature = strings.TrimPrefix(signature, "sha256=")

		mac := hmac.New(sha256.New, []byte(hook.secret))
		_, _ = mac.Write(payload)
		expectedMAC := hex.EncodeToString(mac.Sum(nil))

		if !hmac.Equal([]byte(signature), []byte(expectedMAC)) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("HMAC verification failed"))
			return
		}

		log.Printf("Signature OK! Now processing")

		err = nil
		switch gitHubEvent {
		case CheckRunEvent:
			err = GenericHandle(payload, hook.handlers.CheckRunEvent)
		case CheckSuiteEvent:
			err = GenericHandle(payload, hook.handlers.CheckSuiteEvent)
		case CommitCommentEvent:
			err = GenericHandle(payload, hook.handlers.CommitCommentEvent)
		case CreateEvent:
			err = GenericHandle(payload, hook.handlers.CreateEvent)
		case DeleteEvent:
			err = GenericHandle(payload, hook.handlers.DeleteEvent)
		case DependabotAlertEvent:
			err = GenericHandle(payload, hook.handlers.DependabotAlertEvent)
		case DeployKeyEvent:
			err = GenericHandle(payload, hook.handlers.DeployKeyEvent)
		case DeploymentEvent:
			err = GenericHandle(payload, hook.handlers.DeploymentEvent)
		case DeploymentStatusEvent:
			err = GenericHandle(payload, hook.handlers.DeploymentStatusEvent)
		case ForkEvent:
			err = GenericHandle(payload, hook.handlers.ForkEvent)
		case GollumEvent:
			err = GenericHandle(payload, hook.handlers.GollumEvent)
		case InstallationEvent:
			err = GenericHandle(payload, hook.handlers.InstallationEvent)
		case InstallationRepositoriesEvent:
			err = GenericHandle(payload, hook.handlers.InstallationRepositoriesEvent)
		case IntegrationInstallationEvent:
			err = GenericHandle(payload, hook.handlers.IntegrationInstallationEvent)
		case IntegrationInstallationRepositoriesEvent:
			err = GenericHandle(payload, hook.handlers.IntegrationInstallationRepositoriesEvent)
		case IssueCommentEvent:
			err = GenericHandle(payload, hook.handlers.IssueCommentEvent)
		case IssuesEvent:
			err = GenericHandle(payload, hook.handlers.IssuesEvent)
		case LabelEvent:
			err = GenericHandle(payload, hook.handlers.LabelEvent)
		case MemberEvent:
			err = GenericHandle(payload, hook.handlers.MemberEvent)
		case MembershipEvent:
			err = GenericHandle(payload, hook.handlers.MembershipEvent)
		case MilestoneEvent:
			err = GenericHandle(payload, hook.handlers.MilestoneEvent)
		case MetaEvent:
			err = GenericHandle(payload, hook.handlers.MetaEvent)
		case OrganizationEvent:
			err = GenericHandle(payload, hook.handlers.OrganizationEvent)
		case OrgBlockEvent:
			err = GenericHandle(payload, hook.handlers.OrgBlockEvent)
		case PageBuildEvent:
			err = GenericHandle(payload, hook.handlers.PageBuildEvent)
		case PingEvent:
			err = GenericHandle(payload, hook.handlers.PingEvent)
		case ProjectCardEvent:
			err = GenericHandle(payload, hook.handlers.ProjectCardEvent)
		case ProjectColumnEvent:
			err = GenericHandle(payload, hook.handlers.ProjectColumnEvent)
		case ProjectEvent:
			err = GenericHandle(payload, hook.handlers.ProjectEvent)
		case PublicEvent:
			err = GenericHandle(payload, hook.handlers.PublicEvent)
		case PullRequestEvent:
			err = GenericHandle(payload, hook.handlers.PullRequestEvent)
		case PullRequestReviewEvent:
			err = GenericHandle(payload, hook.handlers.PullRequestReviewEvent)
		case PullRequestReviewCommentEvent:
			err = GenericHandle(payload, hook.handlers.PullRequestReviewCommentEvent)
		case PushEvent:
			err = GenericHandle(payload, hook.handlers.PushEvent)
		case ReleaseEvent:
			err = GenericHandle(payload, hook.handlers.ReleaseEvent)
		case RepositoryEvent:
			err = GenericHandle(payload, hook.handlers.RepositoryEvent)
		case RepositoryVulnerabilityAlertEvent:
			err = GenericHandle(payload, hook.handlers.RepositoryVulnerabilityAlertEvent)
		case SecurityAdvisoryEvent:
			err = GenericHandle(payload, hook.handlers.SecurityAdvisoryEvent)
		case StatusEvent:
			err = GenericHandle(payload, hook.handlers.StatusEvent)
		case TeamEvent:
			err = GenericHandle(payload, hook.handlers.TeamEvent)
		case TeamAddEvent:
			err = GenericHandle(payload, hook.handlers.TeamAddEvent)
		case WatchEvent:
			err = GenericHandle(payload, hook.handlers.WatchEvent)
		case WorkflowDispatchEvent:
			err = GenericHandle(payload, hook.handlers.WorkflowDispatchEvent)
		case WorkflowJobEvent:
			err = GenericHandle(payload, hook.handlers.WorkflowJobEvent)
		case WorkflowRunEvent:
			err = GenericHandle(payload, hook.handlers.WorkflowRunEvent)
		case GitHubAppAuthorizationEvent:
			err = GenericHandle(payload, hook.handlers.GitHubAppAuthorizationEvent)
		case CodeScanningAlertEvent:
			err = GenericHandle(payload, hook.handlers.CodeScanningAlertEvent)
		default:
			w.WriteHeader(http.StatusOK)
		}

		w.WriteHeader(http.StatusOK)
		if err != nil {
			log.Fatalf("Error processing event", err, string(payload))
		}
	}, nil
}
