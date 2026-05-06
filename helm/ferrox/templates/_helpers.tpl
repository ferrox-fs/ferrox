{{/* Common labels and selectors. */}}
{{- define "ferrox.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ferrox.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "ferrox.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ferrox.labels" -}}
app.kubernetes.io/name: {{ include "ferrox.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "ferrox.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ferrox.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
