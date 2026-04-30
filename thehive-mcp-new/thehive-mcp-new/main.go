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

// query runs a TheHive v5 /api/v1/query request.
func (c *TheHiveClient) query(stages []map[string]interface{}) ([]map[string]interface{}, error) {
	resp, err := c.client.R().
		SetBody(map[string]interface{}{"query": stages}).
		Post("/api/v1/query")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() >= 400 {
		return nil, fmt.Errorf("TheHive API error %d: %s", resp.StatusCode(), resp.String())
	}
	var result []map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, fmt.Errorf("parse error: %w — body: %s", err, resp.String())
	}
	return result, nil
}

func (c *TheHiveClient) GetAlerts() ([]map[string]interface{}, error) {
	return c.query([]map[string]interface{}{
		{"_name": "listAlert"},
		{"_name": "sort", "_fields": []map[string]string{{"_createdAt": "desc"}}},
		{"_name": "page", "from": 0, "to": 50},
	})
}

func (c *TheHiveClient) CreateAlert(alert map[string]interface{}) (map[string]interface{}, error) {
	resp, err := c.client.R().SetBody(alert).Post("/api/v1/alert")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() >= 400 {
		return nil, fmt.Errorf("TheHive API error %d: %s", resp.StatusCode(), resp.String())
	}
	var result map[string]interface{}
	err = json.Unmarshal(resp.Body(), &result)
	return result, err
}

func (c *TheHiveClient) GetCases() ([]map[string]interface{}, error) {
	return c.query([]map[string]interface{}{
		{"_name": "listCase"},
		{"_name": "sort", "_fields": []map[string]string{{"_createdAt": "desc"}}},
		{"_name": "page", "from": 0, "to": 50},
	})
}

func (c *TheHiveClient) CreateCase(caseData map[string]interface{}) (map[string]interface{}, error) {
	resp, err := c.client.R().SetBody(caseData).Post("/api/v1/case")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() >= 400 {
		return nil, fmt.Errorf("TheHive API error %d: %s", resp.StatusCode(), resp.String())
	}
	var result map[string]interface{}
	err = json.Unmarshal(resp.Body(), &result)
	return result, err
}

func (c *TheHiveClient) GetTasks(caseId string) ([]map[string]interface{}, error) {
	return c.query([]map[string]interface{}{
		{"_name": "getCase", "idOrName": caseId},
		{"_name": "tasks"},
		{"_name": "sort", "_fields": []map[string]string{{"_createdAt": "asc"}}},
	})
}

func (c *TheHiveClient) CreateTask(caseId string, task map[string]interface{}) (map[string]interface{}, error) {
	resp, err := c.client.R().SetBody(task).Post(fmt.Sprintf("/api/v1/case/%s/task", caseId))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() >= 400 {
		return nil, fmt.Errorf("TheHive API error %d: %s", resp.StatusCode(), resp.String())
	}
	var result map[string]interface{}
	err = json.Unmarshal(resp.Body(), &result)
	return result, err
}

func (c *TheHiveClient) GetObservables(caseId string) ([]map[string]interface{}, error) {
	return c.query([]map[string]interface{}{
		{"_name": "getCase", "idOrName": caseId},
		{"_name": "observables"},
		{"_name": "sort", "_fields": []map[string]string{{"_createdAt": "desc"}}},
	})
}

func (c *TheHiveClient) CreateObservable(caseId string, observable map[string]interface{}) (map[string]interface{}, error) {
	resp, err := c.client.R().SetBody(observable).Post(fmt.Sprintf("/api/v1/case/%s/observable", caseId))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() >= 400 {
		return nil, fmt.Errorf("TheHive API error %d: %s", resp.StatusCode(), resp.String())
	}
	var result []map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		// Some versions return a single object
		var single map[string]interface{}
		if err2 := json.Unmarshal(resp.Body(), &single); err2 == nil {
			return single, nil
		}
		return nil, err
	}
	if len(result) > 0 {
		return result[0], nil
	}
	return nil, fmt.Errorf("no observable created")
}

func (c *TheHiveClient) GetLogs(caseId string) ([]map[string]interface{}, error) {
	return c.query([]map[string]interface{}{
		{"_name": "getCase", "idOrName": caseId},
		{"_name": "logs"},
		{"_name": "sort", "_fields": []map[string]string{{"_createdAt": "desc"}}},
	})
}

func (c *TheHiveClient) CreateLog(caseId string, logEntry map[string]interface{}) (map[string]interface{}, error) {
	resp, err := c.client.R().SetBody(logEntry).Post(fmt.Sprintf("/api/v1/case/%s/log", caseId))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() >= 400 {
		return nil, fmt.Errorf("TheHive API error %d: %s", resp.StatusCode(), resp.String())
	}
	var result map[string]interface{}
	err = json.Unmarshal(resp.Body(), &result)
	return result, err
}

func (c *TheHiveClient) GetAttachments(caseId string) ([]map[string]interface{}, error) {
	return c.query([]map[string]interface{}{
		{"_name": "getCase", "idOrName": caseId},
		{"_name": "attachments"},
	})
}

func main() {
	baseURL := strings.TrimSuffix(os.Getenv("THEHIVE_URL"), "/")
	apiKey := os.Getenv("THEHIVE_API_KEY")
	if baseURL == "" || apiKey == "" {
		log.Fatal("THEHIVE_URL and THEHIVE_API_KEY must be set")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	thehive := NewTheHiveClient(baseURL, apiKey)

	s := server.NewMCPServer("TheHive MCP Server", "1.0.0")

	// ── Tools ──────────────────────────────────────────────────────

	s.AddTool(mcp.NewTool("get-alerts",
		mcp.WithDescription("Get recent alerts from TheHive (SP-CM)"),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		alerts, err := thehive.GetAlerts()
		if err != nil {
			return nil, err
		}
		content, _ := json.Marshal(alerts)
		return &mcp.CallToolResult{Content: []mcp.Content{mcp.TextContent{Type: "text", Text: string(content)}}}, nil
	})

	s.AddTool(mcp.NewTool("create-alert",
		mcp.WithDescription("Create a new alert in TheHive (SP-CM)"),
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
		mcp.WithDescription("Get recent cases from TheHive (SP-CM)"),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		cases, err := thehive.GetCases()
		if err != nil {
			return nil, err
		}
		content, _ := json.Marshal(cases)
		return &mcp.CallToolResult{Content: []mcp.Content{mcp.TextContent{Type: "text", Text: string(content)}}}, nil
	})

	s.AddTool(mcp.NewTool("create-case",
		mcp.WithDescription("Create a new case in TheHive (SP-CM)"),
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
		mcp.WithDescription("Get observables (IOCs) for a case"),
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
		mcp.WithDescription("Create an observable (IOC) for a case"),
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
		mcp.WithDescription("Create a log entry for a case"),
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

	// ── HTTP server: Streamable HTTP transport + health endpoint ──────
	// n8n MCP client (typeVersion 1.2+) uses Streamable HTTP — POSTs to /mcp
	httpServer := server.NewStreamableHTTPServer(s,
		server.WithEndpointPath("/mcp"),
	)

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok","service":"thehive-mcp","port":"%s"}`, port)
	})

	mux.Handle("/mcp", httpServer)

	log.Printf("TheHive MCP Server starting on :%s (Streamable HTTP at /mcp)", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
