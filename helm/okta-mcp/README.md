# Okta MCP Helm Chart

Helm chart for deploying the Okta MCP Server on Kubernetes with production-grade configuration.

## Prerequisites

- Kubernetes 1.24+
- Helm 3.8+
- Docker image built and pushed to registry (or available in GitHub Container Registry)
- Okta domain and API credentials
- Model provider API key (OpenAI, Anthropic, or Groq)

## Quick Start

```bash
# Build and push image (if not using GitHub Container Registry)
docker build --target http -t ghcr.io/strike48/okta-mcp-server:latest .
docker push ghcr.io/strike48/okta-mcp-server:latest

# Install chart
helm install okta-mcp ./helm/okta-mcp \
  --set config.oktaDomain=dev-12345.okta.com \
  --set config.oktaApiToken=your-api-token \
  --set config.modelApiKey=your-openai-key \
  --namespace okta-mcp \
  --create-namespace
```

## Configuration

### Image Configuration

```yaml
image:
  repository: ghcr.io/strike48/okta-mcp-server
  tag: "latest"
  pullPolicy: IfNotPresent
  variant: "http"  # Options: stdio, http, sse

imagePullSecrets:
  - name: ghcr-secret  # Optional: for private registries
```

**Note:** The Dockerfile has three variants (stdio, http, sse). For Kubernetes deployments, use `http` or `sse` variants.

### Okta Configuration

```yaml
config:
  oktaDomain: "dev-12345.okta.com"        # Required: Your Okta domain
  oktaApiToken: "your-api-token"          # Required: Okta API token
  oktaAuthMethod: "api_token"             # Options: api_token, oauth
  oktaClientId: ""                        # Optional: For OAuth
  oktaClientSecret: ""                    # Optional: For OAuth (use secrets)
```

**Security Best Practice:** Use Kubernetes secrets or external secret management (e.g., Vault, AWS Secrets Manager) for sensitive credentials:

```bash
# Create secret manually
kubectl create secret generic okta-mcp-secrets \
  --from-literal=okta-api-token=your-token \
  --from-literal=model-api-key=your-key \
  -n okta-mcp

# Reference in deployment
# (See secrets section below)
```

### Model Provider Configuration

```yaml
config:
  modelProvider: "openai"                 # Options: openai, anthropic, groq
  modelName: "gpt-4"                      # Model to use
  apiKey: "your-api-key"                  # Use secrets in production
```

### Transport Configuration

```yaml
config:
  transportType: "http"                   # Options: stdio, http, sse
  mcpPort: 3000
  mcpHost: "0.0.0.0"
  iUnderstandTheRisks: "false"            # Set to "true" for SSE (deprecated)
```

### Scaling

```yaml
# Fixed replicas
replicaCount: 2

# OR Horizontal Pod Autoscaling
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80
```

### Resource Limits

```yaml
resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

**Recommendations:**
- **Small**: 100m CPU / 128Mi memory (dev/test)
- **Medium**: 250m CPU / 256Mi memory (staging)
- **Large**: 500m CPU / 512Mi memory (production)

### Service Configuration

```yaml
service:
  type: ClusterIP          # ClusterIP|LoadBalancer|NodePort
  port: 3000
  sessionAffinity: ClientIP
  sessionAffinityConfig:
    clientIP:
      timeoutSeconds: 10800  # 3 hours for long MCP sessions
```

### Ingress

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/proxy-read-timeout: "300"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "300"
  hosts:
    - host: okta-mcp.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: okta-mcp-tls
      hosts:
        - okta-mcp.example.com
```

### Health Checks

```yaml
healthCheck:
  livenessProbe:
    httpGet:
      path: /health
      port: http
    initialDelaySeconds: 30
    periodSeconds: 10
    timeoutSeconds: 5
    failureThreshold: 3

  readinessProbe:
    httpGet:
      path: /health
      port: http
    initialDelaySeconds: 5
    periodSeconds: 5
    timeoutSeconds: 3
    failureThreshold: 3

  startupProbe:
    httpGet:
      path: /health
      port: http
    initialDelaySeconds: 10
    periodSeconds: 5
    timeoutSeconds: 3
    failureThreshold: 10
```

### Security

```yaml
podSecurityContext:
  runAsNonRoot: true
  runAsUser: 1001
  runAsGroup: 1001
  fsGroup: 1001
  seccompProfile:
    type: RuntimeDefault

securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: false
  runAsNonRoot: true
  runAsUser: 1001
  capabilities:
    drop:
      - ALL
```

### Network Policies

```yaml
networkPolicy:
  enabled: true
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: 3000
  egress:
    # DNS
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: UDP
          port: 53
    # HTTPS to Okta API and Model Providers
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: 443
```

### High Availability

```yaml
podDisruptionBudget:
  enabled: true
  minAvailable: 1  # Keep at least 1 pod running during updates

affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchExpressions:
              - key: app.kubernetes.io/name
                operator: In
                values:
                  - okta-mcp
          topologyKey: kubernetes.io/hostname
```

## Installation Examples

### Development

```bash
helm install okta-mcp ./helm/okta-mcp \
  --set replicaCount=1 \
  --set config.logLevel=debug \
  --set config.oktaDomain=dev-12345.okta.com \
  --set config.oktaApiToken=your-token \
  --set config.modelApiKey=your-key \
  --set resources.limits.memory=256Mi \
  --namespace okta-dev \
  --create-namespace
```

### Production

```bash
helm install okta-mcp ./helm/okta-mcp \
  --set image.repository=ghcr.io/strike48/okta-mcp-server \
  --set image.tag=1.0.0 \
  --set replicaCount=3 \
  --set autoscaling.enabled=true \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=okta-mcp.example.com \
  --set config.oktaDomain=your-domain.okta.com \
  --set secrets.enabled=true \
  --set secrets.oktaApiToken=your-token \
  --set secrets.modelApiKey=your-key \
  --namespace okta-mcp \
  --create-namespace
```

### Local Development (Colima/Kind)

```bash
# Build image locally
docker build --target http -t okta-mcp-server:latest .

# Load into Colima
colima ssh -- docker pull okta-mcp-server:latest || true

# Install with local values
helm install okta-mcp ./helm/okta-mcp \
  -f ./helm/okta-mcp/values-local.yaml \
  --set config.oktaDomain=dev-12345.okta.com \
  --set config.oktaApiToken=your-token \
  --set config.modelApiKey=your-key \
  --namespace okta-mcp \
  --create-namespace

# Access via NodePort
kubectl port-forward -n okta-mcp svc/okta-mcp 3000:3000
```

### With Custom Values File

Create `production-values.yaml`:

```yaml
replicaCount: 3

image:
  repository: ghcr.io/strike48/okta-mcp-server
  tag: "1.0.0"
  variant: "http"

resources:
  limits:
    cpu: 1000m
    memory: 1Gi
  requests:
    cpu: 500m
    memory: 512Mi

config:
  logLevel: info
  oktaDomain: "your-domain.okta.com"
  modelProvider: "openai"
  modelName: "gpt-4"

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 20

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: okta-mcp.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: okta-mcp-tls
      hosts:
        - okta-mcp.example.com

secrets:
  enabled: true
  oktaApiToken: "your-okta-token"
  modelApiKey: "your-openai-key"
```

Install:

```bash
helm install okta-mcp ./helm/okta-mcp -f production-values.yaml -n okta-mcp
```

## Using GitHub Container Registry

The Docker workflow automatically pushes images to GitHub Container Registry. To use them:

```bash
# Create image pull secret
kubectl create secret docker-registry ghcr-secret \
  --docker-server=ghcr.io \
  --docker-username=your-github-username \
  --docker-password=your-github-pat \
  -n okta-mcp

# Install with GHCR image
helm install okta-mcp ./helm/okta-mcp \
  --set image.repository=ghcr.io/strike48/okta-mcp-server \
  --set image.tag=latest \
  --set imagePullSecrets[0].name=ghcr-secret \
  --namespace okta-mcp
```

## Upgrading

```bash
# Upgrade with new image version
helm upgrade okta-mcp ./helm/okta-mcp \
  --set image.tag=1.1.0 \
  --namespace okta-mcp

# Upgrade with values file
helm upgrade okta-mcp ./helm/okta-mcp -f production-values.yaml -n okta-mcp

# Dry run to preview changes
helm upgrade okta-mcp ./helm/okta-mcp --dry-run --debug -n okta-mcp
```

## Uninstalling

```bash
helm uninstall okta-mcp -n okta-mcp
```

## Monitoring

### Check Status

```bash
# Deployment status
helm status okta-mcp -n okta-mcp

# Pod status
kubectl get pods -n okta-mcp -l app.kubernetes.io/name=okta-mcp

# Service status
kubectl get svc -n okta-mcp -l app.kubernetes.io/name=okta-mcp
```

### View Logs

```bash
# All pods
kubectl logs -n okta-mcp -l app.kubernetes.io/name=okta-mcp -f

# Specific pod
kubectl logs -n okta-mcp okta-mcp-pod-name -f

# Previous crashed pod
kubectl logs -n okta-mcp okta-mcp-pod-name --previous
```

### Health Check

```bash
# Port forward to local
kubectl port-forward -n okta-mcp svc/okta-mcp 3000:3000

# Check health
curl http://localhost:3000/health
```

### Metrics

```bash
# Pod resource usage
kubectl top pods -n okta-mcp -l app.kubernetes.io/name=okta-mcp

# Node resource usage
kubectl top nodes
```

## Troubleshooting

### Pods Not Starting

```bash
# Describe pod
kubectl describe pod -n okta-mcp okta-mcp-pod-name

# Check events
kubectl get events -n okta-mcp --sort-by='.lastTimestamp'

# Check image pull
kubectl get pods -n okta-mcp -o jsonpath='{.items[*].status.containerStatuses[*].state}'
```

### Image Pull Failures

```bash
# Check image pull secrets
kubectl get secrets -n okta-mcp

# Create GHCR secret
kubectl create secret docker-registry ghcr-secret \
  --docker-server=ghcr.io \
  --docker-username=your-username \
  --docker-password=your-pat \
  -n okta-mcp

# Update values
helm upgrade okta-mcp ./helm/okta-mcp \
  --set imagePullSecrets[0].name=ghcr-secret \
  -n okta-mcp
```

### Network Issues

```bash
# Test connectivity from pod
kubectl exec -n okta-mcp okta-mcp-pod-name -- wget -O- https://your-domain.okta.com

# Check network policies
kubectl get networkpolicies -n okta-mcp
kubectl describe networkpolicy okta-mcp -n okta-mcp
```

### Okta API Connection Issues

```bash
# Check Okta credentials
kubectl exec -n okta-mcp okta-mcp-pod-name -- env | grep OKTA

# Test Okta API from pod
kubectl exec -n okta-mcp okta-mcp-pod-name -- \
  curl -H "Authorization: SSWS your-token" \
  https://your-domain.okta.com/api/v1/users?limit=1
```

### Resource Limits

```bash
# Check if pods are being OOMKilled
kubectl get pods -n okta-mcp -o jsonpath='{.items[*].status.containerStatuses[*].lastState.terminated.reason}'

# Increase memory limits
helm upgrade okta-mcp ./helm/okta-mcp \
  --set resources.limits.memory=1Gi \
  -n okta-mcp
```

## Production Checklist

- [ ] Image built and pushed to registry
- [ ] Resource limits configured
- [ ] Autoscaling enabled (minReplicas ≥ 2)
- [ ] PodDisruptionBudget enabled
- [ ] Health checks configured
- [ ] Network policies enabled
- [ ] Ingress with TLS configured
- [ ] Secrets managed externally (Vault/AWS Secrets Manager)
- [ ] Monitoring/alerting set up
- [ ] Backup/disaster recovery plan
- [ ] Security scan passed
- [ ] Load testing performed
- [ ] Okta API rate limits considered
- [ ] Model provider API limits considered

## Security Best Practices

1. **Run as non-root**: Already configured (UID 1001)
2. **Drop all capabilities**: Configured in securityContext
3. **Enable network policies**: Restrict egress/ingress
4. **Use external secret management**: Never hardcode tokens
5. **Scan images**: Use Trivy or similar
6. **Keep dependencies updated**: Regular security updates
7. **Enable Pod Security Standards**: Use baseline/restricted
8. **Rotate Okta API tokens**: Regular rotation policy
9. **Limit Okta API permissions**: Use principle of least privilege
10. **Monitor API usage**: Track for anomalies

## Performance Tuning

### Small Load (<100 req/min)
```yaml
replicaCount: 2
resources:
  limits: { cpu: 250m, memory: 256Mi }
  requests: { cpu: 100m, memory: 128Mi }
```

### Medium Load (100-1000 req/min)
```yaml
replicaCount: 3
resources:
  limits: { cpu: 500m, memory: 512Mi }
  requests: { cpu: 250m, memory: 256Mi }
autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
```

### High Load (>1000 req/min)
```yaml
replicaCount: 5
resources:
  limits: { cpu: 1000m, memory: 1Gi }
  requests: { cpu: 500m, memory: 512Mi }
autoscaling:
  enabled: true
  minReplicas: 5
  maxReplicas: 20
```

## Docker Variants

The Dockerfile supports three variants:

1. **stdio** (default): For Claude Desktop and similar STDIO-based clients
2. **http**: For web applications and HTTP-based integrations (recommended for Kubernetes)
3. **sse**: Server-Sent Events (deprecated, legacy support)

Specify the variant in your values:

```yaml
image:
  variant: "http"  # stdio, http, or sse
```

## CI/CD Integration

The repository includes GitHub Actions workflows:

- **CI Workflow** (`.github/workflows/ci.yml`): Tests and validates code
- **Docker Workflow** (`.github/workflows/docker.yml`): Builds and pushes multi-arch images

Images are automatically published to:
```
ghcr.io/strike48/okta-mcp-server:latest
ghcr.io/strike48/okta-mcp-server:http-latest
ghcr.io/strike48/okta-mcp-server:sse-latest
ghcr.io/strike48/okta-mcp-server:stdio-latest
ghcr.io/strike48/okta-mcp-server:<date>-<sha>
```

## Support

- Issues: https://github.com/strike48/okta-mcp-server/issues
- Documentation: https://github.com/strike48/okta-mcp-server

## License

See LICENSE file in the repository root.

