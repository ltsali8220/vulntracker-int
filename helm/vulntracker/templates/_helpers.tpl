{{- define "vulntracker.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "vulntracker.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "vulntracker.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "vulntracker.labels" -}}
app.kubernetes.io/name: {{ include "vulntracker.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end }}

{{- define "vulntracker.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vulntracker.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* Images are deployed by immutable digest only; a mutable tag can be re-pointed */}}
{{- define "vulntracker.image" -}}
{{- printf "%s@%s" .Values.image.repository (required "image.digest is required (sha256:...)" .Values.image.digest) }}
{{- end }}

{{- define "vulntracker.namespace" -}}
{{- default .Release.Namespace .Values.namespace }}
{{- end }}
