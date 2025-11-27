# HTTP Header-Based Authentication

This document describes how to use HTTP headers to pass Okta credentials to the MCP server instead of environment variables.

## Overview

The Okta MCP server supports two methods for providing Okta credentials:

1. **Environment Variables** (traditional method)
2. **HTTP Headers** (new method, useful for dynamic configurations)

HTTP headers take precedence over environment variables, allowing different credentials per-request.

## HTTP Headers

### Required Headers

- `X-Okta-Domain`: Your Okta organization URL (e.g., `https://your-org.okta.com`)
- `X-Okta-Token`: Your Okta API token

### Example Request

```bash
curl -X POST http://localhost:3005/mcp \
  -H "Content-Type: application/json" \
  -H "X-Okta-Domain: https://your-org.okta.com" \
  -H "X-Okta-Token: your_api_token_here" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/list",
    "params": {}
  }'
```

## Use Cases

### 1. Multi-Tenant Applications

Serve multiple Okta organizations from a single MCP server instance:

```python
# Client A uses their credentials
headers_a = {
    "X-Okta-Domain": "https://org-a.okta.com",
    "X-Okta-Token": "token_for_org_a"
}

# Client B uses their credentials
headers_b = {
    "X-Okta-Domain": "https://org-b.okta.com",
    "X-Okta-Token": "token_for_org_b"
}
```

### 2. Elixir Matrix Configuration

This is particularly useful when integrating with the Elixir Matrix workflow system:

```elixir
headers_template: %{
  "X-Okta-Token" => "{{secrets.okta_api_token}}",
  "X-Okta-Domain" => "{{secrets.okta_org_url}}"
}
```

### 3. Secrets Management

Store credentials in a secrets manager instead of environment variables:

```python
import httpx
from my_secrets import get_secret

async def call_okta_mcp(tool_name, arguments):
    headers = {
        "X-Okta-Domain": get_secret("okta_domain"),
        "X-Okta-Token": get_secret("okta_token")
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://mcp-server:3005/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": arguments
                }
            }
        )
        return response.json()
```

## Priority Order

Credentials are resolved in the following order:

1. **HTTP Headers** (`X-Okta-Domain`, `X-Okta-Token`)
2. **Environment Variables** (`OKTA_CLIENT_ORGURL`, `OKTA_API_TOKEN`)

If both are provided, HTTP headers take precedence.

## Server Configuration

### Starting the Server

The server no longer requires environment variables to start:

```bash
# Start without environment variables
uv run python main.py --http --iunderstandtherisks --host 0.0.0.0 --port 3005

# Or with environment variables as fallback
export OKTA_CLIENT_ORGURL=https://your-org.okta.com
export OKTA_API_TOKEN=your_api_token_here
uv run python main.py --http --iunderstandtherisks --host 0.0.0.0 --port 3005
```

### Warning Messages

If environment variables are not set, the server will log warnings but continue running:

```
2025-11-26 19:49:48,158 - okta_mcp - WARNING - Missing Okta environment variables: OKTA_CLIENT_ORGURL, OKTA_API_TOKEN
2025-11-26 19:49:48,158 - okta_mcp - WARNING - Server will start. Okta tools will work if credentials are provided via:
2025-11-26 19:49:48,158 - okta_mcp - WARNING - 
2025-11-26 19:49:48,158 - okta_mcp - WARNING - Option 1: HTTP Headers (recommended for dynamic configuration)
2025-11-26 19:49:48,158 - okta_mcp - WARNING -   X-Okta-Domain: https://your-org.okta.com
2025-11-26 19:49:48,158 - okta_mcp - WARNING -   X-Okta-Token: your_api_token_here
```

## Implementation Details

### Middleware

The `OktaHeaderAuthMiddleware` extracts credentials from HTTP headers and stores them in context variables that are accessible throughout the request lifecycle.

### Context Variables

Credentials are stored in Python context variables:
- `okta_org_url_context`: Stores the Okta domain
- `okta_api_token_context`: Stores the API token

These are automatically cleaned up after each request.

### Client Initialization

The `OktaMcpClient` checks context variables first, then falls back to environment variables when initializing the Okta SDK client.

## Security Considerations

1. **Always use HTTPS** in production to protect credentials in transit
2. **Rotate API tokens** regularly
3. **Use secrets management** systems instead of hardcoding credentials
4. **Network isolation**: Bind to `127.0.0.1` instead of `0.0.0.0` when not needed
5. **Monitor access**: Enable request logging to track credential usage

## Testing

Test the header authentication feature:

```bash
# Run the test script
python test_header_auth.py
```

Or manually test with curl:

```bash
# Test tools/list endpoint
curl -X POST http://localhost:3005/mcp \
  -H "Content-Type: application/json" \
  -H "X-Okta-Domain: https://your-org.okta.com" \
  -H "X-Okta-Token: your_token" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# Test actual tool call
curl -X POST http://localhost:3005/mcp \
  -H "Content-Type: application/json" \
  -H "X-Okta-Domain: https://your-org.okta.com" \
  -H "X-Okta-Token: your_token" \
  -d '{
    "jsonrpc":"2.0",
    "id":2,
    "method":"tools/call",
    "params":{
      "name":"list_okta_users",
      "arguments":{"limit":5}
    }
  }'
```

## Troubleshooting

### Credentials Not Found

If you see errors about missing Okta configuration:

```
ValueError: Okta configuration required. Either:
1. Pass via HTTP headers: X-Okta-Domain and X-Okta-Token
2. Set environment variables: OKTA_CLIENT_ORGURL and OKTA_API_TOKEN
```

**Solution**: Ensure you're passing the headers with every request, or set environment variables.

### Headers Not Being Read

If headers aren't being recognized:

1. Check that you're using the exact header names: `X-Okta-Domain` and `X-Okta-Token`
2. Verify the server is running in HTTP mode (`--http` flag)
3. Check server logs for "Using Okta credentials from X-Okta-Token header" message

### Multiple Credentials

If using both environment variables and headers:
- Headers will be used for that specific request
- Environment variables remain as fallback for requests without headers

## Migration Guide

### From Environment Variables Only

**Before:**
```bash
export OKTA_CLIENT_ORGURL=https://your-org.okta.com
export OKTA_API_TOKEN=your_token
uv run python main.py --http --iunderstandtherisks
```

**After (with headers):**
```bash
# Server can start without environment variables
uv run python main.py --http --iunderstandtherisks

# Pass credentials in each request
curl ... -H "X-Okta-Domain: https://your-org.okta.com" -H "X-Okta-Token: your_token"
```

### Hybrid Approach

You can use both methods simultaneously:

```bash
# Set default credentials via environment
export OKTA_CLIENT_ORGURL=https://default-org.okta.com
export OKTA_API_TOKEN=default_token

# Start server
uv run python main.py --http --iunderstandtherisks

# Some requests use default (no headers)
curl ... http://localhost:3005/mcp

# Other requests override with headers
curl ... -H "X-Okta-Domain: https://other-org.okta.com" -H "X-Okta-Token: other_token"
```

## API Reference

### Headers

| Header | Required | Description | Example |
|--------|----------|-------------|---------|
| `X-Okta-Domain` | Yes* | Okta organization URL | `https://your-org.okta.com` |
| `X-Okta-Token` | Yes* | Okta API token | `00abc...xyz` |

*Required if not set in environment variables

### Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `OKTA_CLIENT_ORGURL` | No** | Okta organization URL | `https://your-org.okta.com` |
| `OKTA_API_TOKEN` | No** | Okta API token | `00abc...xyz` |

**Not required if passing credentials via headers

