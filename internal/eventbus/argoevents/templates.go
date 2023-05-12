package argoevents

import (
	"bytes"
	"html/template"
)

var (
	tmplEventSourceGitlab            = "eventSourceGitlab"
	tmplEventSourceGitlabEventName   = "eventSourceGitlabEventName"
	tmplGitlabAccessToken            = "gitlabAccessToken"
	tmplGitlabSecretToken            = "gitlabSecretToken"
	tmplGitlabEventSourcePath        = "gitlabEventSourcePath"
	tmplGitlabEndPoint               = "gitlabEndPoint"
	tmplGitlabIngressName            = "gitlabIngressName"
	tmplGitlabServiceName            = "gitlabServiceName"
	tmplEventSourceCalendar          = "eventSourceCalendar"
	tmplEventSourceCalendarEventName = "eventSourceCalendarEventName"
	tmplTriggerName                  = "triggerName"
	tmplDependencyName               = "dependencyName"
	tmplSensorName                   = "sensorName"
	tmplTektonInitPipeline           = "tektonInitPipeline"
	tmplVaultEngineGitAcessTokenPath = "vaultEngineGitAcessTokenPath"
	nameAndInitPipelineTemplates     = map[string]string{
		tmplEventSourceGitlab:            "{{ .productName }}-{{ .runtimeName }}-gitlab",
		tmplEventSourceGitlabEventName:   "{{ .repoName }}",
		tmplGitlabAccessToken:            "{{ .productName }}-{{ .runtimeName }}-{{ .repoName }}-accesstoken",
		tmplGitlabSecretToken:            "{{ .productName }}-{{ .runtimeName }}-{{ .eventName }}-secrettoken",
		tmplGitlabEventSourcePath:        "/{{ .clusterName }}-{{ .productName }}-{{ .runtimeName }}-gitlab",
		tmplGitlabEndPoint:               "/{{ .clusterName }}-{{ .productName }}-{{ .runtimeName }}-gitlab/{{ .repoName }}",
		tmplGitlabIngressName:            "{{ .clusterName }}-{{ .productName }}-{{ .runtimeName }}-gitlab",
		tmplGitlabServiceName:            "{{ .clusterName }}-{{ .productName }}-{{ .runtimeName }}-gitlab",
		tmplEventSourceCalendar:          "{{ .productName }}-{{ .runtimeName }}-calendar",
		tmplEventSourceCalendarEventName: "{{ .eventName }}",
		tmplDependencyName:               "{{ .runtimeName }}-{{ .eventSourceType }}-{{ .eventName }}",
		tmplTriggerName:                  "{{ .eventName }}-{{ .pipelineName }}-{{ .eventSourceType }}",
		tmplSensorName:                   "{{ .productName }}-{{ .runtimeName }}",
		tmplVaultEngineGitAcessTokenPath: "{{ .pipelineRepoProviderType }}/{{ .pipelineRepoID }}/default/accesstoken-api",
		tmplTektonInitPipeline:           templateTektonInitPipeline,
	}
)

var (
	keyEventName                = "eventName"
	keyPipelineName             = "pipelineName"
	keyProductName              = "productName"
	keyRuntimeName              = "runtimeName"
	keyRepoName                 = "repoName"
	keyClusterName              = "clusterName"
	keyEventSourceType          = "eventSourceType"
	keyPipelineRepoProviderType = "pipelineRepoProviderType"
	keyPipelineRepoID           = "pipelineRepoID"
	keyPipelineRepoURL          = "pipelineRepoURL"
	keyPipelinePath             = "pipelinePath"
	keyIsCodeRepoTrigger        = "isCodeRepoTrigger"
)

type eventType string

var (
	eventTypeGitlab   eventType = "gitlab"
	eventTypeCalendar eventType = "calendar"
)

func getStringFromTemplate(templateName string, vars interface{}) (string, error) {
	tmpl, err := template.New(templateName).Parse(nameAndInitPipelineTemplates[templateName])
	if err != nil {
		return "", err
	}

	var path bytes.Buffer
	err = tmpl.Execute(&path, vars)
	if err != nil {
		return "", err
	}
	return path.String(), nil
}

var templateTektonInitPipeline = `
apiVersion: tekton.dev/v1beta1
kind: PipelineRun
metadata:
  generateName: init-pipiline-
spec:
  params:
    - name: PIPELINE-REVISION
      value: main
    {{- if eq .isCodeRepoTrigger "true" }}
    - name: REVISION
      value: main
    {{- end }}
    - name: runfile
      value: {{ .pipelinePath }}
  taskRunSpecs:
    - pipelineTaskName: git-clone
      metadata:
        annotations:
          vault.hashicorp.com/agent-inject: 'true'
          vault.hashicorp.com/tls-secret: "ca"
          vault.hashicorp.com/ca-cert: "/vault/tls/ca.crt"
          vault.hashicorp.com/agent-pre-populate-only: "true"
          vault.hashicorp.com/role: '{{ .runtimeName }}'
          vault.hashicorp.com/agent-run-as-user: '0'
          vault.hashicorp.com/agent-run-as-group: '0'
          vault.hashicorp.com/agent-inject-secret-id_ecdsa: "git/data/{{ .pipelineRepoProviderType }}/{{ .pipelineRepoID }}/default/readonly"
          vault.hashicorp.com/secret-volume-path-id_ecdsa: "/root/.ssh"
          vault.hashicorp.com/agent-inject-perms-id_ecdsa: '0400'
          vault.hashicorp.com/agent-inject-template-id_ecdsa: |
            {{ "{{-" }} with secret "git/data/{{ .pipelineRepoProviderType }}/{{ .pipelineRepoID }}/default/readonly" {{ "-}}" }}
            {{ "{{" }} .Data.data.deploykey {{ "}}" }}
            {{ "{{-" }} end {{ "-}}" }}
  pipelineSpec:
    params:
      - name: PIPELINE-REVISION
      {{- if eq .isCodeRepoTrigger "true" }}
      - name: REVISION
      {{- end }}
    tasks:
      - name: git-clone
        taskRef:
          name: git-clone
          kind: ClusterTask
        workspaces:
          - name: output
            workspace: source-volume
        params:
          - name: url
            value: {{ .pipelineRepoURL }}
          - name: revision
            value: $(params.PIPELINE-REVISION)
      - name: pipeline-run
        runAfter:
          - git-clone
        taskRef:
          name: kubernetes-actions
          kind: ClusterTask
        params:
          - name: image
            value: gcr.io/cloud-builders/kubectl@sha256:c373e04fcc64c448e6cf9ebdde6fe67bb8c10b0df682da9210e1e965606b3af6
          - name: script
            value: |
              SUFFIX=` + "`openssl rand -hex 2`" + `
		      {{- if eq .isCodeRepoTrigger "true" }}
              REF=$(params.REVISION)
              BRANCH=${REF/refs\/heads\//}
      		  {{- end }}

              cat > ./kustomization.yaml << EOF
              apiVersion: kustomize.config.k8s.io/v1beta1
              kind: Kustomization
              resources:
              - $(params.runfile)
              nameSuffix: -${SUFFIX}
      		  {{- if eq .isCodeRepoTrigger "true" }}
              commonLabels:
                branch: $BRANCH
              patches:
              - patch: |-
                - op: replace
                  path: /spec/params/0/value
                  value: $(params.REVISION)
                target:
                kind: PipelineRun
      		  {{- end }}
              EOF
              cat ./kustomization.yaml
              kubectl kustomize . | kubectl -n {{ .runtimeName }} create -f -
  workspaces:
    - name: source-volume
      volumeClaimTemplate:
        spec:
          accessModes:
            - ReadWriteOnce
          resources:
            requests:
            storage: 10M
`
