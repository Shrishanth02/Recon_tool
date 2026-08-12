{{/*
Expand the name of the chart.
*/}}
{{- define "reconx.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a fully qualified app name.
*/}}
{{- define "reconx.fullname" -}}
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
Chart name and version as used by the chart label.
*/}}
{{- define "reconx.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels.
*/}}
{{- define "reconx.labels" -}}
helm.sh/chart: {{ include "reconx.chart" . }}
{{ include "reconx.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels.
*/}}
{{- define "reconx.selectorLabels" -}}
app.kubernetes.io/name: {{ include "reconx.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Component-specific selector labels. Usage: include "reconx.componentSelectorLabels" (dict "root" . "component" "backend")
*/}}
{{- define "reconx.componentSelectorLabels" -}}
{{ include "reconx.selectorLabels" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
Name of the Secret holding app secrets (existing or chart-managed).
*/}}
{{- define "reconx.secretName" -}}
{{- if .Values.existingSecret -}}
{{- .Values.existingSecret -}}
{{- else -}}
{{- include "reconx.fullname" . -}}
{{- end -}}
{{- end -}}

{{/*
Name of the ConfigMap holding non-secret app config.
*/}}
{{- define "reconx.configMapName" -}}
{{- printf "%s-config" (include "reconx.fullname" .) -}}
{{- end -}}

{{/*
Resolved DATABASE_URL: explicit override, else derived from postgresql or externalDatabase.
*/}}
{{- define "reconx.databaseUrl" -}}
{{- if .Values.env.databaseUrl -}}
{{- .Values.env.databaseUrl -}}
{{- else if .Values.postgresql.enabled -}}
{{- printf "postgresql://%s:%s@%s:%v/%s" .Values.postgresql.auth.username .Values.postgresql.auth.password .Values.postgresql.host (.Values.postgresql.port | int) .Values.postgresql.auth.database -}}
{{- else -}}
{{- .Values.externalDatabase.url -}}
{{- end -}}
{{- end -}}

{{/*
Resolved REDIS_URL: explicit override, else derived from redis or externalRedis.
*/}}
{{- define "reconx.redisUrl" -}}
{{- if .Values.env.redisUrl -}}
{{- .Values.env.redisUrl -}}
{{- else if .Values.redis.enabled -}}
{{- printf "redis://%s:%v/0" .Values.redis.host (.Values.redis.port | int) -}}
{{- else -}}
{{- .Values.externalRedis.url -}}
{{- end -}}
{{- end -}}

{{/*
ServiceAccount name.
*/}}
{{- define "reconx.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "reconx.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}
