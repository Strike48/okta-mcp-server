{{/*
Expand the name of the chart.
*/}}
{{- define "okta-mcp.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "okta-mcp.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "okta-mcp.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "okta-mcp.labels" -}}
helm.sh/chart: {{ include "okta-mcp.chart" . }}
{{ include "okta-mcp.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "okta-mcp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "okta-mcp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "okta-mcp.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "okta-mcp.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Get the image tag based on variant
*/}}
{{- define "okta-mcp.imageTag" -}}
{{- if eq .Values.image.variant "stdio" }}
{{- printf "%s" (.Values.image.tag | default .Chart.AppVersion) }}
{{- else if eq .Values.image.variant "http" }}
{{- printf "%s" (.Values.image.tag | default .Chart.AppVersion) }}
{{- else if eq .Values.image.variant "sse" }}
{{- printf "%s" (.Values.image.tag | default .Chart.AppVersion) }}
{{- else }}
{{- printf "%s" (.Values.image.tag | default .Chart.AppVersion) }}
{{- end }}
{{- end }}

