package llm

import (
	"AIxVuln/misc"
	"context"
	"fmt"
	"strings"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/openai/openai-go/v3/responses"
)

// OpenAIResponsesClient implements Client using the official openai/openai-go
// SDK's Responses API.
type OpenAIResponsesClient struct {
	cli           openai.Client
	configSection string
}

// NewOpenAIResponsesClient creates a client that uses the official OpenAI
// Responses API. configSection is the config.ini section (e.g. "decision",
// "ops") used to read per-section overrides such as STREAM.
func NewOpenAIResponsesClient(configSection string, opts ...option.RequestOption) *OpenAIResponsesClient {
	return &OpenAIResponsesClient{
		cli:           openai.NewClient(opts...),
		configSection: configSection,
	}
}

// Chat implements Client.Chat via the Responses API.
// It reads the "STREAM" config from the client's config section first, then
// falls back to [main_setting]. In streaming mode, it collects the full
// response internally so the caller always receives a complete Response.
func (c *OpenAIResponsesClient) Chat(ctx context.Context, model string, messages []Message, tools []ToolDef) (Response, error) {
	// Build input items from the message history.
	items := messagesToInputItems(messages)

	params := responses.ResponseNewParams{
		Model: openai.ChatModel(model),
		Input: responses.ResponseNewParamsInputUnion{
			OfInputItemList: items,
		},
		Store: openai.Bool(false),
	}

	// Add tool definitions if any.
	if len(tools) > 0 {
		params.Tools = toolDefsToResponsesTools(tools)
	}

	streamVal := misc.GetConfigValueDefault(c.configSection, "STREAM", "")
	if streamVal == "" {
		streamVal = misc.GetConfigValueDefault("main_setting", "STREAM", "false")
	}
	useStream := strings.EqualFold(streamVal, "true")

	if useStream {
		return c.chatStream(ctx, params)
	}
	return c.chatSync(ctx, params)
}

// chatSync performs a non-streaming request.
func (c *OpenAIResponsesClient) chatSync(ctx context.Context, params responses.ResponseNewParams) (Response, error) {
	resp, err := c.cli.Responses.New(ctx, params)
	if err != nil {
		return Response{}, err
	}
	return fromResponsesOutput(resp)
}

// chatStream performs a streaming request and collects the completed response.
func (c *OpenAIResponsesClient) chatStream(ctx context.Context, params responses.ResponseNewParams) (Response, error) {
	stream := c.cli.Responses.NewStreaming(ctx, params)
	defer stream.Close()

	var completed *responses.Response
	for stream.Next() {
		evt := stream.Current()
		if evt.Type == "response.completed" {
			rc := evt.AsResponseCompleted()
			completed = &rc.Response
		}
	}
	if err := stream.Err(); err != nil {
		return Response{}, err
	}
	if completed == nil {
		return Response{}, fmt.Errorf("stream ended without response.completed event")
	}
	return fromResponsesOutput(completed)
}

// --- conversion helpers: llm types → Responses API params ---

// messagesToInputItems converts []Message to the Responses API input format.
// system messages → Instructions field is NOT used here; instead we pass them
// as EasyInputMessage with role "system"/"developer" which the API accepts.
func messagesToInputItems(msgs []Message) responses.ResponseInputParam {
	items := make(responses.ResponseInputParam, 0, len(msgs))
	for _, m := range msgs {
		switch m.Role {
		case RoleSystem, RoleUser:
			role := EasyInputRole(m.Role)
			items = append(items, responses.ResponseInputItemUnionParam{
				OfMessage: &responses.EasyInputMessageParam{
					Role: role,
					Content: responses.EasyInputMessageContentUnionParam{
						OfString: openai.String(m.Content),
					},
				},
			})

		case RoleAssistant:
			// If the assistant message has no tool calls, emit it as a message.
			if len(m.ToolCalls) == 0 {
				items = append(items, responses.ResponseInputItemUnionParam{
					OfMessage: &responses.EasyInputMessageParam{
						Role: responses.EasyInputMessageRoleAssistant,
						Content: responses.EasyInputMessageContentUnionParam{
							OfString: openai.String(m.Content),
						},
					},
				})
			} else {
				// Emit the text part as a message if non-empty.
				if m.Content != "" {
					items = append(items, responses.ResponseInputItemUnionParam{
						OfMessage: &responses.EasyInputMessageParam{
							Role: responses.EasyInputMessageRoleAssistant,
							Content: responses.EasyInputMessageContentUnionParam{
								OfString: openai.String(m.Content),
							},
						},
					})
				}
				// Emit each tool call as a separate function_call item.
				for _, tc := range m.ToolCalls {
					items = append(items, responses.ResponseInputItemUnionParam{
						OfFunctionCall: &responses.ResponseFunctionToolCallParam{
							CallID:    tc.ID,
							Name:      tc.Name,
							Arguments: tc.Arguments,
						},
					})
				}
			}

		case RoleTool:
			items = append(items, responses.ResponseInputItemUnionParam{
				OfFunctionCallOutput: &responses.ResponseInputItemFunctionCallOutputParam{
					CallID: m.ToolCallID,
					Output: responses.ResponseInputItemFunctionCallOutputOutputUnionParam{
						OfString: openai.String(m.Content),
					},
				},
			})
		}
	}
	return items
}

// EasyInputRole maps our role constants to the SDK's EasyInputMessageRole.
func EasyInputRole(role string) responses.EasyInputMessageRole {
	switch role {
	case RoleSystem:
		return responses.EasyInputMessageRoleSystem
	case RoleUser:
		return responses.EasyInputMessageRoleUser
	case RoleAssistant:
		return responses.EasyInputMessageRoleAssistant
	default:
		return responses.EasyInputMessageRole(role)
	}
}

// toolDefsToResponsesTools converts []ToolDef to the Responses API tool format.
func toolDefsToResponsesTools(defs []ToolDef) []responses.ToolUnionParam {
	out := make([]responses.ToolUnionParam, len(defs))
	for i, d := range defs {
		out[i] = responses.ToolUnionParam{
			OfFunction: &responses.FunctionToolParam{
				Name:        d.Name,
				Description: openai.String(d.Description),
				Parameters:  d.Parameters,
			},
		}
	}
	return out
}

// --- conversion helpers: Responses API output → llm types ---

// fromResponsesOutput extracts text content and tool calls from the response.
func fromResponsesOutput(resp *responses.Response) (Response, error) {
	var r Response
	for _, item := range resp.Output {
		switch item.Type {
		case "message":
			// Extract text content from the message.
			for _, c := range item.Content {
				if c.Type == "output_text" {
					r.Content += c.Text
				}
			}
		case "function_call":
			fc := item.AsFunctionCall()
			r.ToolCalls = append(r.ToolCalls, ToolCall{
				ID:        fc.CallID,
				Name:      fc.Name,
				Arguments: fc.Arguments,
			})
		}
	}
	// Extract usage.
	if resp.Usage.TotalTokens > 0 {
		r.Usage = Usage{
			PromptTokens:     resp.Usage.InputTokens,
			CompletionTokens: resp.Usage.OutputTokens,
			TotalTokens:      resp.Usage.TotalTokens,
		}
	}
	// Fallback: use OutputText() if we didn't find content above.
	if r.Content == "" && len(r.ToolCalls) == 0 {
		r.Content = resp.OutputText()
	}
	if r.Content == "" && len(r.ToolCalls) == 0 {
		return Response{}, fmt.Errorf("empty response (status=%s)", resp.Status)
	}
	return r, nil
}
