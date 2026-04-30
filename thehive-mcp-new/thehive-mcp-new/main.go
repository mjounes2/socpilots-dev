package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/go-resty/resty/v2"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type TheHiveClient struct {
	client *resty.Client
}

func NewTheHiveClient(baseURL, apiKey string) *TheHiveClient {
	client := resty.New().
		SetBaseURL(baseURL).
		SetHeader("Authorization", "Bearer "+apiKey).
		SetHeader("Content-Type", "application/json")

	return &TheHiveClient{client: client}
}

func (c *TheHiveClient) GetAlerts() ([]map[string]interface{}, error) {
	resp, err := c.client.R().Get("/api/alert")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("API error: %s", resp.String())
	}
	var alerts []map[string]interface{}
	err = json.Unmarshal(resp.Body(), &alerts)
	return alerts, err
}

func (c *TheHiveClient) CreateAlert(alert map[string]interface{}) (map[string]interface{}, error) {
	resp, err := c.client.R().SetBody(alert).Post("/api/alert")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() != 201 {
		return nil, fmt.Errorf("API error: %s", resp.String())
	}
	var result map[string]interface{}
	err = json.Unmarshal(resp.Body(), &result)
	return result, err
}

func (c *TheHiveClient) GetCases() ([]map[string]interface{}, error) {
	resp, err := c.client.R().Get("/api/case")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("API error: %s", resp.String())
	}
	var cases []map[string]interface{}
	err = json.Unmarshal(resp.Body(), &cases)
	return cases, err
}

func (c *TheHiveClient) CreateCase(caseData map[string]interface{}) (map[string]interface{}, error) {
	resp, err := c.client.R().SetBody(caseData).Post("/api/case")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() != 201 {
		return nil, fmt.Errorf("API error: %s", resp.String())
	}
	var result map[string]interface{}
	err = json.Unmarshal(resp.Body(), &result)
	return result, err
}

func (c *TheHiveClient) GetTasks(caseId string) ([]map[string]interface{}, error) {
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"_and": []map[string]interface{}{
				{"_parent": map[string]interface{}{
					"_type": "case",
					"_query": map[string]interface{}{
						"_id": caseId,
					},
				}},
			},
		},
	}
	resp, err := c.client.R().SetBody(query).Post("/api/case/task/_search")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("API error: %s", resp.String())
	}
	var tasks []map[string]interface{}
	err = json.Unmarshal(resp.Body(), &tasks)
	return tasks, err
}

func (c *TheHiveClient) CreateTask(caseId string, task map[string]interface{}) (map[string]interface{}, error) {
	resp, err := c.client.R().SetBody(task).Post(fmt.Sprintf("/api/case/%s/task", caseId))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() != 201 {
		return nil, fmt.Errorf("API error: %s", resp.String())
	}
	var result map[string]interface{}
	err = json.Unmarshal(resp.Body(), &result)
	return result, err
}

func (c *TheHiveClient) GetObservables(caseId string) ([]map[string]interface{}, error) {
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"_and": []map[string]interface{}{
				{"_parent": map[string]interface{}{
					"_type": "case",
					"_query": map[string]interface{}{
						"_id": caseId,
					},
				}},
			},
		},
	}
	resp, err := c.client.R().SetBody(query).Post("/api/case/artifact/_search")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("API error: %s", resp.String())
	}
	var observables []map[string]interface{}
	err = json.Unmarshal(resp.Body(), &observables)
	return observables, err
}

func (c *TheHiveClient) CreateObservable(caseId string, observable map[string]interface{}) (map[string]interface{}, error) {
	resp, err := c.client.R().SetBody(observable).Post(fmt.Sprintf("/api/case/%s/artifact", caseId))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() != 201 {
		return nil, fmt.Errorf("API error: %s", resp.String())
	}
	var result []map[string]interface{}
	err = json.Unmarshal(resp.Body(), &result)
	if err != nil {
		return nil, err
	}
	if len(result) > 0 {
		return result[0], nil
	}
	return nil, fmt.Errorf("No observable created")
}

func (c *TheHiveClient) GetLogs(caseId string) ([]map[string]interface{}, error) {
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"_and": []map[string]interface{}{
				{"_parent": map[string]interface{}{
					"_type": "case",
					"_query": map[string]interface{}{
						"_id": caseId,
					},
				}},
			},
		},
	}
	resp, err := c.client.R().SetBody(query).Post("/api/case/log/_search")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("API error: %s", resp.String())
	}
	var logs []map[string]interface{}
	err = json.Unmarshal(resp.Body(), &logs)
	return logs, err
}

func (c *TheHiveClient) CreateLog(caseId string, logEntry map[string]interface{}) (map[string]interface{}, error) {
	resp, err := c.client.R().SetBody(logEntry).Post(fmt.Sprintf("/api/case/%s/log", caseId))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() != 201 {
		return nil, fmt.Errorf("API error: %s", resp.String())
	}
	var result map[string]interface{}
	err = json.Unmarshal(resp.Body(), &result)
	return result, err
}

func (c *TheHiveClient) GetAttachments(caseId string) ([]map[string]interface{}, error) {
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"_and": []map[string]interface{}{
				{"_parent": map[string]interface{}{
					"_type": "case",
					"_query": map[string]interface{}{
						"_id": caseId,
					},
				}},
			},
		},
	}
	resp, err := c.client.R().SetBody(query).Post("/api/case/attachment/_search")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("API error: %s", resp.String())
	}
	var attachments []map[string]interface{}
	err = json.Unmarshal(resp.Body(), &attachments)
	return attachments, err
}

func main() {
	baseURL := strings.TrimSuffix(os.Getenv("THEHIVE_URL"), "/api")
	apiKey := os.Getenv("THEHIVE_API_KEY")
	if baseURL == "" || apiKey == "" {
		log.Fatal("THEHIVE_URL and THEHIVE_API_KEY must be set")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// MCP_BASE_URL is the URL clients use to reach this server's /message endpoint.
	// Must match what n8n (or other MCP clients) will POST to after receiving the SSE endpoint event.
	mcpBaseURL := os.Getenv("MCP_BASE_URL")
	if mcpBaseURL == "" {
		mcpBaseURL = fmt.Sprintf("http://thehive-mcp:%s", port)
	}

	thehive := NewTheHiveClient(baseURL, apiKey)

	s := server.NewMCPServer("TheHive MCP Server", "1.0.0")

	// ── Tools ──────────────────────────────────────────────────────

	s.AddTool(mcp.NewTool("get-alerts",
		mcp.WithDescription("Get all alerts from TheHive"),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		alerts, err := thehive.GetAlerts()
		if err != nil {
			return nil, err
		}
		content, _ := json.Marshal(alerts)
		return &mcp.CallToolResult{Content: []mcp.Content{mcp.TextContent{Type: "text", Text: string(content)}}}, nil
	})

	s.AddTool(mcp.NewTool("create-alert",
		mcp.WithDescription("Create a new alert in TheHive"),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := request.Params.Arguments.(map[string]interface{})
		alert, err := thehive.CreateAlert(args)
		if err != nil {
			return nil, err
		}
		content, _ := json.Marshal(alert)
		return &mcp.CallToolResult{Content: []mcp.Content{mcp.TextContent{Type: "text", Text: string(content)}}}, nil
	})

	s.AddTool(mcp.NewTool("get-cases",
		mcp.WithDescription("Get all cases from TheHive"),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		cases, err := thehive.GetCases()
		if err != nil {
			return nil, err
		}
		content, _ := json.Marshal(cases)
		return &mcp.CallToolResult{Content: []mcp.Content{mcp.TextContent{Type: "text", Text: string(content)}}}, nil
	})

	s.AddTool(mcp.NewTool("create-case",
		mcp.WithDescription("Create a new case in TheHive"),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := request.Params.Arguments.(map[string]interface{})
		caseObj, err := thehive.CreateCase(args)
		if err != nil {
			return nil, err
		}
		content, _ := json.Marshal(caseObj)
		return &mcp.CallToolResult{Content: []mcp.Content{mcp.TextContent{Type: "text", Text: string(content)}}}, nil
	})

	s.AddTool(mcp.NewTool("get-tasks",
		mcp.WithDescription("Get tasks for a case"),
		mcp.WithString("caseId", mcp.Required(), mcp.Description("Case ID")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		caseId, _ := request.RequireString("caseId")
		tasks, err := thehive.GetTasks(caseId)
		if err != nil {
			return nil, err
		}
		content, _ := json.Marshal(tasks)
		return &mcp.CallToolResult{Content: []mcp.Content{mcp.TextContent{Type: "text", Text: string(content)}}}, nil
	})

	s.AddTool(mcp.NewTool("create-task",
		mcp.WithDescription("Create a task for a case"),
		mcp.WithString("caseId", mcp.Required(), mcp.Description("Case ID")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		caseId, _ := request.RequireString("caseId")
		args := request.Params.Arguments.(map[string]interface{})
		delete(args, "caseId")
		task, err := thehive.CreateTask(caseId, args)
		if err != nil {
			return nil, err
		}
		content, _ := json.Marshal(task)
		return &mcp.CallToolResult{Content: []mcp.Content{mcp.TextContent{Type: "text", Text: string(content)}}}, nil
	})

	s.AddTool(mcp.NewTool("get-observables",
		mcp.WithDescription("Get observables for a case"),
		mcp.WithString("caseId", mcp.Required(), mcp.Description("Case ID")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		caseId, _ := request.RequireString("caseId")
		observables, err := thehive.GetObservables(caseId)
		if err != nil {
			return nil, err
		}
		content, _ := json.Marshal(observables)
		return &mcp.CallToolResult{Content: []mcp.Content{mcp.TextContent{Type: "text", Text: string(content)}}}, nil
	})

	s.AddTool(mcp.NewTool("create-observable",
		mcp.WithDescription("Create an observable for a case"),
		mcp.WithString("caseId", mcp.Required(), mcp.Description("Case ID")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		caseId, _ := request.RequireString("caseId")
		args := request.Params.Arguments.(map[string]interface{})
		delete(args, "caseId")
		observable, err := thehive.CreateObservable(caseId, args)
		if err != nil {
			return nil, err
		}
		content, _ := json.Marshal(observable)
		return &mcp.CallToolResult{Content: []mcp.Content{mcp.TextContent{Type: "text", Text: string(content)}}}, nil
	})

	s.AddTool(mcp.NewTool("get-logs",
		mcp.WithDescription("Get logs for a case"),
		mcp.WithString("caseId", mcp.Required(), mcp.Description("Case ID")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		caseId, _ := request.RequireString("caseId")
		logs, err := thehive.GetLogs(caseId)
		if err != nil {
			return nil, err
		}
		content, _ := json.Marshal(logs)
		return &mcp.CallToolResult{Content: []mcp.Content{mcp.TextContent{Type: "text", Text: string(content)}}}, nil
	})

	s.AddTool(mcp.NewTool("create-log",
		mcp.WithDescription("Create a log for a case"),
		mcp.WithString("caseId", mcp.Required(), mcp.Description("Case ID")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		caseId, _ := request.RequireString("caseId")
		args := request.Params.Arguments.(map[string]interface{})
		delete(args, "caseId")
		logEntry, err := thehive.CreateLog(caseId, args)
		if err != nil {
			return nil, err
		}
		content, _ := json.Marshal(logEntry)
		return &mcp.CallToolResult{Content: []mcp.Content{mcp.TextContent{Type: "text", Text: string(content)}}}, nil
	})

	s.AddTool(mcp.NewTool("get-attachments",
		mcp.WithDescription("Get attachments for a case"),
		mcp.WithString("caseId", mcp.Required(), mcp.Description("Case ID")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		caseId, _ := request.RequireString("caseId")
		attachments, err := thehive.GetAttachments(caseId)
		if err != nil {
			return nil, err
		}
		content, _ := json.Marshal(attachments)
		return &mcp.CallToolResult{Content: []mcp.Content{mcp.TextContent{Type: "text", Text: string(content)}}}, nil
	})

	// ── HTTP server: SSE transport + health endpoint ───────────────

	// SSE server — n8n connects to /sse, sends messages to /message
	// WithBaseURL sets the message endpoint URL returned in the SSE event — must be
	// reachable by the MCP client (n8n uses the Docker service name).
	sseServer := server.NewSSEServer(s,
		server.WithBaseURL(mcpBaseURL),
	)

	mux := http.NewServeMux()

	// Health check for Docker healthcheck and monitoring
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok","service":"thehive-mcp","port":"%s"}`, port)
	})

	// Mount SSE server — handles /sse and /message
	mux.Handle("/", sseServer)

	log.Printf("TheHive MCP Server starting on :%s (SSE at /sse, messages at /message)", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
