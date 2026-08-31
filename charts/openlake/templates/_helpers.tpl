{{- define "openlake.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "openlake.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "openlake.labels" -}}
app.kubernetes.io/name: {{ include "openlake.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
openlake.dev/mode: {{ if .Values.kv.enabled }}kv{{ else }}{{ .Values.mode }}{{ end }}
{{- if .Values.kv.enabled }}
openlake.dev/workload: kv
{{- else }}
openlake.dev/workload: storage
{{- end }}
{{- end -}}

{{- define "openlake.selectorLabels" -}}
app.kubernetes.io/name: {{ include "openlake.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "openlake.vllmSmokeTest.fullname" -}}
{{- printf "%s-vllm-smoke" (include "openlake.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "openlake.kv.connectorDevice" -}}
{{- if .Values.kv.connector.device -}}
{{- .Values.kv.connector.device -}}
{{- else if eq .Values.kv.transport "h2" -}}
local
{{- else if eq .Values.kv.rdma.backend "ucx" -}}
ucx
{{- else -}}
{{- .Values.kv.rdma.devName -}}
{{- end -}}
{{- end -}}

{{- define "openlake.vllmSmokeTest.validate" -}}
{{- if .Values.vllmSmokeTest.enabled -}}
  {{- if not .Values.kv.enabled -}}
    {{- fail "vllmSmokeTest.enabled=true requires kv.enabled=true" -}}
  {{- end -}}
  {{- include "openlake.kv.validate" . -}}
  {{- if ne .Values.kv.transport "h2" -}}
    {{- fail "the CPU vLLM smoke test requires kv.transport=h2" -}}
  {{- end -}}
  {{- if ne (len .Values.kv.targets) 1 -}}
    {{- fail "the H2/local vLLM smoke test requires exactly one kv.targets entry" -}}
  {{- end -}}
  {{- if not .Values.kv.connector.enabled -}}
    {{- fail "the vLLM smoke test requires kv.connector.enabled=true" -}}
  {{- end -}}
{{- end -}}
{{- end -}}

{{- define "openlake.kv.validate" -}}
{{- if .Values.kv.enabled -}}
  {{- if not .Values.kv.targets -}}
    {{- fail "kv.enabled=true requires at least one kv.targets entry" -}}
  {{- end -}}
  {{- if not (has .Values.kv.transport (list "h2" "rdma")) -}}
    {{- fail "kv.transport must be h2 or rdma" -}}
  {{- end -}}
  {{- if gt (len .Values.kv.targets) 65536 -}}
    {{- fail "kv.targets cannot contain more than 65536 entries (OpenLake node IDs are u16)" -}}
  {{- end -}}
  {{- if and .Values.kv.connector.enabled (eq .Values.kv.transport "h2") (gt (len .Values.kv.targets) 1) -}}
    {{- fail "the H2/local connector supports one same-host KV target only; disable kv.connector.enabled for a multi-node H2 orchestration smoke test or use the rdma transport" -}}
  {{- end -}}
  {{- if and .Values.kv.connector.enabled (eq .Values.kv.transport "h2") (ne .Values.kv.sharedMemory.type "hostPath") -}}
    {{- fail "the H2/local connector requires kv.sharedMemory.type=hostPath so vLLM and OpenLake can share the POSIX slab" -}}
  {{- end -}}
  {{- if eq (int .Values.kv.ports.rpc) (int .Values.kv.ports.telemetry) -}}
    {{- fail "kv.ports.rpc and kv.ports.telemetry must be different" -}}
  {{- end -}}
  {{- if lt (int .Values.kv.slab.capacityGB) 1 -}}
    {{- fail "kv.slab.capacityGB must be at least 1" -}}
  {{- end -}}
  {{- $nodes := dict -}}
  {{- $ips := dict -}}
  {{- range $index, $target := .Values.kv.targets -}}
    {{- if not $target.nodeName -}}
      {{- fail (printf "kv.targets[%d].nodeName is required" $index) -}}
    {{- end -}}
    {{- if not $target.ip -}}
      {{- fail (printf "kv.targets[%d].ip is required" $index) -}}
    {{- end -}}
    {{- if hasKey $nodes $target.nodeName -}}
      {{- fail (printf "kv.targets contains duplicate nodeName %q" $target.nodeName) -}}
    {{- end -}}
    {{- if hasKey $ips $target.ip -}}
      {{- fail (printf "kv.targets contains duplicate ip %q" $target.ip) -}}
    {{- end -}}
    {{- $_ := set $nodes $target.nodeName true -}}
    {{- $_ := set $ips $target.ip true -}}
  {{- end -}}
  {{- if eq .Values.kv.transport "rdma" -}}
    {{- if not (has .Values.kv.rdma.backend (list "dct" "ucx")) -}}
      {{- fail "kv.rdma.backend must be dct or ucx" -}}
    {{- end -}}
    {{- if and (eq .Values.kv.rdma.backend "dct") (not .Values.kv.rdma.devName) -}}
      {{- fail "kv.rdma.devName is required for the dct backend" -}}
    {{- end -}}
    {{- if and (eq .Values.kv.rdma.backend "dct") (gt (mul (int .Values.kv.rdma.maxClients) (add1 (int .Values.kv.rdma.peerCredit))) (int .Values.kv.rdma.srqDepth)) -}}
      {{- fail "kv.rdma.maxClients x (peerCredit + 1) must not exceed srqDepth" -}}
    {{- end -}}
  {{- end -}}
{{- end -}}
{{- end -}}
