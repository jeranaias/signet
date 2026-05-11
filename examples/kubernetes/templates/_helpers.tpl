{{/*
Expand the name of the chart.
*/}}
{{- define "signet.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "signet.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Chart label.
*/}}
{{- define "signet.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Standard labels.
*/}}
{{- define "signet.labels" -}}
helm.sh/chart: {{ include "signet.chart" . }}
{{ include "signet.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels.
*/}}
{{- define "signet.selectorLabels" -}}
app.kubernetes.io/name: {{ include "signet.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Name of the Secret holding the HMAC key (either user-provided or one
this chart renders).
*/}}
{{- define "signet.hmacSecretName" -}}
{{- if .Values.hmacSecret.existingSecret -}}
{{- .Values.hmacSecret.existingSecret -}}
{{- else -}}
{{- printf "%s-hmac" (include "signet.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Key inside the HMAC secret.
*/}}
{{- define "signet.hmacSecretKey" -}}
{{- if .Values.hmacSecret.existingSecret -}}
{{- .Values.hmacSecret.existingSecretKey -}}
{{- else -}}
secret
{{- end -}}
{{- end -}}
