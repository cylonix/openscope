// Package bedrock is the router's egress to AWS Bedrock.
//
// All InvokeModel / Converse calls flow through this package. The client
// acquires short-lived STS credentials by assuming CustomerRouterInvokeRole
// in the customer's bedrock account, with an external ID. The role's trust
// policy (deploy/aws/iam/customer_router_invoke_role.trust.json) restricts
// who can assume; Bedrock invocation permission is scoped to specific
// inference profiles in customer_router_invoke_role.permissions.json.
//
// We use Bedrock Converse API (unified request shape across providers)
// rather than raw InvokeModel — adding a new model is one Catalog entry
// in pkg/billing, not a per-provider JSON shape adapter.
package bedrock

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	bedrocktypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/openscope/openscope/router/internal/provider"
)

// Client makes Converse calls against Bedrock. Construct one per process;
// it's safe for concurrent use.
//
// The SDK's aws.CredentialsCache wraps the STS AssumeRole provider and
// auto-refreshes credentials before expiry — we don't track or store the
// cache directly. It lives inside c.bedrock's config.
type Client struct {
	region        string
	invokeRoleArn string
	externalID    string
	bedrock       *bedrockruntime.Client
}

// Config holds construction parameters. invokeRoleArn is the
// CustomerRouterInvokeRole in the customer's bedrock account. externalID
// is the rotatable secret from setup_iam.sh (state/external_id_<slug>.txt).
type Config struct {
	Region        string
	InvokeRoleArn string
	ExternalID    string
}

func New(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Region == "" {
		cfg.Region = "us-west-2"
	}
	if cfg.InvokeRoleArn == "" {
		return nil, fmt.Errorf("InvokeRoleArn required")
	}
	if cfg.ExternalID == "" {
		return nil, fmt.Errorf("ExternalID required")
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Region))
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	// AssumeRole provider with external ID + short session (15 min). The
	// SDK's CredentialsCache wraps this provider and auto-refreshes
	// credentials before expiry; we don't have to manage cache TTL.
	stsClient := sts.NewFromConfig(awsCfg)
	provider := stscreds.NewAssumeRoleProvider(stsClient, cfg.InvokeRoleArn, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = "openscope-router"
		o.ExternalID = aws.String(cfg.ExternalID)
		o.Duration = 15 * time.Minute
	})
	credsCache := aws.NewCredentialsCache(provider)

	// Build the Bedrock runtime client with the assumed-role credentials.
	bedrockCfg := awsCfg.Copy()
	bedrockCfg.Credentials = credsCache
	br := bedrockruntime.NewFromConfig(bedrockCfg)

	return &Client{
		region:        cfg.Region,
		invokeRoleArn: cfg.InvokeRoleArn,
		externalID:    cfg.ExternalID,
		bedrock:       br,
	}, nil
}

// Region returns the AWS region the Bedrock runtime client targets. The
// router stamps it onto receipts and surfaces it in the dashboards so an
// auditor can see exactly where each call was served.
func (c *Client) Region() string { return c.region }

// Name identifies the serving platform on receipts and dashboards. The
// pitch is that calls run in the customer's own Bedrock account — so
// "where did my data go" answers concretely: AWS Bedrock, in this region,
// under your account.
func (c *Client) Name() string { return "AWS Bedrock" }

// Invoke runs one Bedrock Converse call. Credentials are acquired (or
// reused from the SDK cache) via assume-role each session.
func (c *Client) Invoke(ctx context.Context, req provider.Request) (*provider.Response, error) {
	if req.ModelID == "" {
		return nil, fmt.Errorf("ModelID required")
	}
	if len(req.Messages) == 0 {
		return nil, fmt.Errorf("at least one message required")
	}
	if req.MaxTokens <= 0 {
		req.MaxTokens = 256
	}

	// Build Bedrock messages, dropping any system messages into the
	// dedicated System block (Bedrock's API separates system from messages).
	var system []bedrocktypes.SystemContentBlock
	var msgs []bedrocktypes.Message
	for _, m := range req.Messages {
		switch m.Role {
		case "system":
			system = append(system, &bedrocktypes.SystemContentBlockMemberText{Value: m.Content})
		case "user":
			msgs = append(msgs, bedrocktypes.Message{
				Role:    bedrocktypes.ConversationRoleUser,
				Content: []bedrocktypes.ContentBlock{&bedrocktypes.ContentBlockMemberText{Value: m.Content}},
			})
		case "assistant":
			msgs = append(msgs, bedrocktypes.Message{
				Role:    bedrocktypes.ConversationRoleAssistant,
				Content: []bedrocktypes.ContentBlock{&bedrocktypes.ContentBlockMemberText{Value: m.Content}},
			})
		default:
			return nil, fmt.Errorf("unsupported role %q", m.Role)
		}
	}

	maxTok := int32(req.MaxTokens)
	in := &bedrockruntime.ConverseInput{
		ModelId:  aws.String(req.ModelID),
		Messages: msgs,
		System:   system,
		InferenceConfig: &bedrocktypes.InferenceConfiguration{
			MaxTokens: aws.Int32(maxTok),
		},
	}

	out, err := c.bedrock.Converse(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("bedrock Converse: %w", err)
	}

	// Extract text from the response. Bedrock returns the assistant
	// message as a discriminated union; we expect a Text block back.
	var text string
	if out.Output != nil {
		if msg, ok := out.Output.(*bedrocktypes.ConverseOutputMemberMessage); ok {
			for _, blk := range msg.Value.Content {
				if t, ok := blk.(*bedrocktypes.ContentBlockMemberText); ok {
					text += t.Value
				}
			}
		}
	}

	resp := &provider.Response{
		ModelID:      req.ModelID,
		Content:      text,
		FinishReason: string(out.StopReason),
	}
	if out.Usage != nil {
		if out.Usage.InputTokens != nil {
			resp.InputTokens = int(*out.Usage.InputTokens)
		}
		if out.Usage.OutputTokens != nil {
			resp.OutputTokens = int(*out.Usage.OutputTokens)
		}
	}
	if out.Metrics != nil && out.Metrics.LatencyMs != nil {
		resp.LatencyMs = *out.Metrics.LatencyMs
	}
	return resp, nil
}
