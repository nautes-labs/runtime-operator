package argoevents

import (
	"bytes"
	"text/template"
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
		tmplVaultEngineGitAcessTokenPath: "{{ .pipelineRepoProviderType }}/{{ .repoName }}/default/accesstoken-api",
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
	keyPipelineLabel            = "pipelineLabel"
	keyServiceAccountName       = "serviceAccountName"
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
