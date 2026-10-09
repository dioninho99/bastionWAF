package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type cloudflare struct {
	token string
	client *http.Client
}

type cfResponse struct {
	Success bool `json:"success"`
	Errors []struct{ Message string `json:"message"` } `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func newCloudflare(token string) *cloudflare {
	return &cloudflare{token: token, client: &http.Client{}}
}

func (c *cloudflare) request(ctx context.Context, method, endpoint string, body any, result any) error {
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://api.cloudflare.com/client/v4"+endpoint, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var envelope cfResponse
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 || !envelope.Success {
		if len(envelope.Errors) > 0 {
			return fmt.Errorf("Cloudflare API: %s", envelope.Errors[0].Message)
		}
		return fmt.Errorf("Cloudflare API returned HTTP %d", resp.StatusCode)
	}
	if result != nil {
		return json.Unmarshal(envelope.Result, result)
	}
	return nil
}

func (c *cloudflare) zone(ctx context.Context, name string) (string, error) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	name = strings.TrimPrefix(name, "*.")
	labels := strings.Split(name, ".")
	for i := 0; i < len(labels)-1; i++ {
		candidate := strings.Join(labels[i:], ".")
		type zone struct{ ID, Name string }
		var zones []zone
		if err := c.request(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(candidate)+"&status=active&per_page=1", nil, &zones); err != nil {
			return "", err
		}
		if len(zones) > 0 {
			return zones[0].ID, nil
		}
	}
	return "", fmt.Errorf("no active Cloudflare zone found for %s", name)
}

func (c *cloudflare) setTXT(ctx context.Context, zoneID, name, content string) (string, error) {
	type record struct {
		ID string `json:"id"`
	}
	var created record
	err := c.request(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", map[string]any{
		"type": "TXT", "name": name, "content": content, "ttl": 60,
	}, &created)
	return created.ID, err
}

func (c *cloudflare) deleteTXT(ctx context.Context, zoneID, id string) error {
	if id == "" {
		return nil
	}
	return c.request(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+id, nil, nil)
}
