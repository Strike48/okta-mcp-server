# Port Configuration Guide

The Okta MCP Server port is configurable via multiple methods. The default port is **3000**, but you can override it as needed.

## Configuration Methods

### 1. Environment Variable (Recommended)

Set the `PORT` environment variable before running the application:

```bash
export PORT=8080
python main.py --http --host=0.0.0.0 --iunderstandtherisks
```

### 2. Docker Run Command

When running the Docker container, pass the `PORT` environment variable:

```bash
# Using environment variable
docker run -e PORT=8080 -p 8080:8080 okta-mcp-server:http

# Using a different external port mapping
docker run -e PORT=9000 -p 3000:9000 okta-mcp-server:http
```

**Important**: When using a custom port, make sure to:
1. Set the `PORT` environment variable inside the container
2. Update the port mapping (`-p`) to match: `-p <host-port>:<container-port>`

### 3. Command Line Argument

Pass the port directly as a command-line argument:

```bash
python main.py --http --host=0.0.0.0 --port=8080 --iunderstandtherisks
```

### 4. Helm Chart Configuration

When deploying via Helm, modify the `values.yaml` or use `--set`:

```yaml
# values.yaml
config:
  mcpPort: 8080

service:
  port: 8080
```

Or via command line:

```bash
helm install okta-mcp ./helm/okta-mcp \
  --set config.mcpPort=8080 \
  --set service.port=8080
```

### 5. Docker Compose

In your `docker-compose.yml`:

```yaml
version: '3.8'
services:
  okta-mcp:
    image: okta-mcp-server:http
    environment:
      - PORT=8080
    ports:
      - "8080:8080"
```

## Priority Order

The port is determined in the following priority order (highest to lowest):

1. Command-line argument (`--port`)
2. Environment variable (`PORT`)
3. Default value (3000)

## Examples

### Example 1: Run on port 5000

```bash
# Direct execution
PORT=5000 python main.py --http --host=0.0.0.0 --iunderstandtherisks

# Docker
docker run -e PORT=5000 -p 5000:5000 okta-mcp-server:http

# Helm
helm install okta-mcp ./helm/okta-mcp --set config.mcpPort=5000 --set service.port=5000
```

### Example 2: Multiple instances on different ports

```bash
# Instance 1 on port 3000
docker run -d --name okta-mcp-1 -e PORT=3000 -p 3000:3000 okta-mcp-server:http

# Instance 2 on port 3001
docker run -d --name okta-mcp-2 -e PORT=3001 -p 3001:3001 okta-mcp-server:http

# Instance 3 on port 3002
docker run -d --name okta-mcp-3 -e PORT=3002 -p 3002:3002 okta-mcp-server:http
```

### Example 3: Kubernetes with custom port

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: okta-mcp-custom-port
spec:
  template:
    spec:
      containers:
      - name: okta-mcp
        image: okta-mcp-server:http
        env:
        - name: PORT
          value: "8888"
        ports:
        - containerPort: 8888
          name: http
---
apiVersion: v1
kind: Service
metadata:
  name: okta-mcp-service
spec:
  ports:
  - port: 8888
    targetPort: 8888
  selector:
    app: okta-mcp-custom-port
```

## Troubleshooting

### Port already in use

If you get an error like "Address already in use", either:
1. Choose a different port
2. Stop the process using that port

```bash
# Find process using port 3000
lsof -i :3000
# or
netstat -tulpn | grep 3000

# Kill the process
kill -9 <PID>
```

### Port not accessible from outside container

Make sure:
1. The host is set to `0.0.0.0` (not `127.0.0.1`)
2. Port mapping is correct in Docker: `-p <host-port>:<container-port>`
3. Firewall rules allow the port

## Security Notes

- Always use `--iunderstandtherisks` flag when exposing the server over the network
- Consider using a reverse proxy (nginx, Traefik) for production deployments
- Ensure proper authentication is configured when exposing publicly
- Use TLS/SSL certificates for encrypted communication

