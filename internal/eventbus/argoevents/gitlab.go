package argoevents

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"strconv"

	"github.com/argoproj/argo-events/pkg/apis/common"
	eventsourcev1alpha1 "github.com/argoproj/argo-events/pkg/apis/eventsource/v1alpha1"
	sensorv1alpha1 "github.com/argoproj/argo-events/pkg/apis/sensor/v1alpha1"
	"github.com/google/uuid"
	nautescrd "github.com/nautes-labs/pkg/api/v1alpha1"
	nautesutil "github.com/nautes-labs/runtime-operator/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	networkv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// syncEventSourceGitlab is used to create gitlab type argo events eventsource and the related resources that ensure its normal operation.
// It will create the following resources
// - eventsource
// - service
// - ingress
// - secret of gitlab accesstoken
// - secret of webhook
func (s *runtimeSyncer) syncEventSourceGitlab(ctx context.Context) error {
	vars := copyVars(s.vars)
	eventSourceName, err := getStringFromTemplate(tmplEventSourceGitlab, vars)
	if err != nil {
		return err
	}

	spec, err := s.calculateEventSourceGitlab(ctx, s.runtime.Spec.EventSources)
	if err != nil {
		return fmt.Errorf("calculate event source %s failed: %w", eventSourceName, err)
	}
	if spec == nil {
		return s.deleteEventSource(ctx, eventSourceName)
	}

	if err := s.syncEventSource(ctx, eventSourceName, *spec); err != nil {
		return fmt.Errorf("sync event source %s failed: %w", eventSourceName, err)
	}

	return s.syncEventSourceGitlabRelatedResources(ctx, eventSourceName)
}

func (s *runtimeSyncer) syncEventSourceGitlabRelatedResources(ctx context.Context, eventSourceName string) error {
	eventSource := &eventsourcev1alpha1.EventSource{}
	key := types.NamespacedName{
		Namespace: s.config.EventBus.ArgoEvents.Namespace,
		Name:      eventSourceName,
	}
	if err := s.k8sClient.Get(ctx, key, eventSource); err != nil {
		return fmt.Errorf("can not get event source: %w", err)
	}

	vars := copyVars(s.vars)
	serviceName, err := getStringFromTemplate(tmplGitlabServiceName, vars)
	if err != nil {
		return err
	}
	ingressName, err := getStringFromTemplate(tmplGitlabIngressName, vars)
	if err != nil {
		return err
	}

	serviceSpec, err := s.calculateEventSourceServiceGitlab(ctx, vars)
	if err != nil {
		return fmt.Errorf("calculate service %s spec failed: %w", serviceName, err)
	}
	if err := s.syncEventSourceServiceGitlab(ctx, serviceName, eventSource, *serviceSpec); err != nil {
		return fmt.Errorf("sync service %s failed: %w", serviceName, err)
	}

	ingresSpec, err := s.calculateEventSourceIngressGitlab(ctx, vars)
	if err != nil {
		return fmt.Errorf("calculate ingress %s spec failed: %w", ingressName, err)
	}
	if err := s.syncEventSourceIngressGitlab(ctx, ingressName, eventSource, *ingresSpec); err != nil {
		return fmt.Errorf("sync ingress %s failed: %w", ingressName, err)
	}

	for _, gitlabEvent := range eventSource.Spec.Gitlab {
		accessTokenName := gitlabEvent.AccessToken.Name
		if err := s.syncGitlabAccessToken(ctx, accessTokenName, eventSource); err != nil {
			return fmt.Errorf("sync gitlab access token failed: %w", err)
		}

		secretTokenName := gitlabEvent.SecretToken.Name
		if err := s.syncWebhookSecretToken(ctx, secretTokenName, eventSource); err != nil {
			return fmt.Errorf("sync gitlab secret token failed: %w", err)
		}
	}
	return nil
}

func (s *runtimeSyncer) deleteEventSourceGitlab(ctx context.Context) error {
	eventSourceName, err := getStringFromTemplate(tmplEventSourceGitlab, s.vars)
	if err != nil {
		return err
	}

	return s.deleteEventSource(ctx, eventSourceName)
}

const (
	codeRepoProviderCAMountName = "certs-volume"
	gitlabCAConfigMapName       = "ca-certificates"
	gitlabCAMountPath           = "/etc/ssl/certs"
)

const (
	secretKeyAccessToken = "token"
	secretKeySecretToken = "token"
)

// calculateEventSourceGitlab create eventsource.gitlab spec.
// It will loop eventsource in project pipeline eventsources, find out all eventsource witch "gitlab" is not null, and create one argo eventsource.gitlab.
// If gitlab type eventsource is not found, it will return nil.
func (s *runtimeSyncer) calculateEventSourceGitlab(ctx context.Context, eventSources []nautescrd.EventSource) (*eventsourcev1alpha1.EventSourceSpec, error) {
	eventSourceSpec := &eventsourcev1alpha1.EventSourceSpec{
		Gitlab: map[string]eventsourcev1alpha1.GitlabEventSource{},
		Template: &eventsourcev1alpha1.Template{
			Container: &corev1.Container{
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      codeRepoProviderCAMountName,
						MountPath: gitlabCAMountPath,
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: codeRepoProviderCAMountName,
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: gitlabCAConfigMapName,
							},
						},
					},
				},
			},
		},
	}

	for _, evsrc := range eventSources {
		if evsrc.Gitlab == nil {
			continue
		}
		codeRepo := &nautescrd.CodeRepo{}
		if err := s.tenantK8sClient.Get(ctx, types.NamespacedName{
			Namespace: s.productName,
			Name:      evsrc.Gitlab.RepoName,
		}, codeRepo); err != nil {
			return nil, err
		}

		codeRepoProvider := &nautescrd.CodeRepoProvider{}
		if err := s.tenantK8sClient.Get(ctx, types.NamespacedName{
			Namespace: s.config.Nautes.Namespace,
			Name:      codeRepo.Spec.CodeRepoProvider,
		}, codeRepoProvider); err != nil {
			return nil, err
		}

		vars := copyVars(s.vars)
		vars[keyRepoName] = codeRepo.Name
		vars[keyEventName] = evsrc.Name

		eventName, err := getStringFromTemplate(tmplEventSourceGitlabEventName, vars)
		if err != nil {
			return nil, err
		}
		accessTokenName, err := getStringFromTemplate(tmplGitlabAccessToken, vars)
		if err != nil {
			return nil, err
		}
		secretTokenName, err := getStringFromTemplate(tmplGitlabSecretToken, vars)
		if err != nil {
			return nil, err
		}
		endPoint, err := getStringFromTemplate(tmplGitlabEndPoint, vars)
		if err != nil {
			return nil, err
		}

		eventSourceSpec.Gitlab[eventName] = eventsourcev1alpha1.GitlabEventSource{
			Webhook: &eventsourcev1alpha1.WebhookContext{
				Endpoint: endPoint,
				Method:   "POST",
				Port:     strconv.Itoa(int(eventSourcePort)),
				URL:      s.webhookURL,
			},
			Events: codeRepo.Spec.Webhook.Events,
			AccessToken: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: accessTokenName,
				},
				Key: secretKeyAccessToken,
			},
			EnableSSLVerification: false,
			GitlabBaseURL:         codeRepoProvider.Spec.ApiServer,
			DeleteHookOnFinish:    false,
			Projects:              []string{getIDFromCodeRepo(codeRepo.Name)},
			SecretToken: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: secretTokenName,
				},
				Key: secretKeySecretToken,
			},
		}
	}

	if len(eventSourceSpec.Gitlab) == 0 {
		return nil, nil
	}

	return eventSourceSpec, nil
}

func (s *runtimeSyncer) syncGitlabAccessToken(ctx context.Context, name string, owner client.Object) error {
	return nil
}

func (s *runtimeSyncer) syncWebhookSecretToken(ctx context.Context, name string, owner client.Object) error {
	secretToken := &corev1.Secret{}
	key := types.NamespacedName{
		Namespace: s.config.EventBus.ArgoEvents.Namespace,
		Name:      name,
	}

	if err := s.k8sClient.Get(ctx, key, secretToken); err != nil {
		if apierrors.IsNotFound(err) {
			token := uuid.New().String()
			secretToken := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      key.Name,
					Namespace: key.Namespace,
				},
				Data: map[string][]byte{
					"token": []byte(token),
				},
			}

			err = controllerutil.SetOwnerReference(owner, secretToken, scheme)
			if err != nil {
				return fmt.Errorf("can not set secret %s's owner: %w", name, err)
			}
			return s.k8sClient.Create(ctx, secretToken)
		}
		return err
	}

	if nautesutil.IsOwner(owner, secretToken, scheme) {
		return nil
	}

	err := controllerutil.SetOwnerReference(owner, secretToken, scheme)
	if err != nil {
		return fmt.Errorf("can not set secret %s's owner: %w", name, err)
	}

	return s.k8sClient.Update(ctx, secretToken)
}

func (s *runtimeSyncer) syncEventSourceServiceGitlab(ctx context.Context, name string, owner client.Object, spec corev1.ServiceSpec) error {
	key := types.NamespacedName{
		Namespace: s.config.EventBus.ArgoEvents.Namespace,
		Name:      name,
	}

	service := &corev1.Service{}
	if err := s.k8sClient.Get(ctx, key, service); err != nil {
		if apierrors.IsNotFound(err) {
			service = &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      key.Name,
					Namespace: key.Namespace,
				},
			}
		} else {
			return fmt.Errorf("get service %s failed: %w", name, err)
		}
	}

	needUpdate := false
	if !nautesutil.IsOwner(owner, service, scheme) {
		if err := controllerutil.SetOwnerReference(owner, service, scheme); err != nil {
			return fmt.Errorf("set service %s owner failed: %w", key.Name, err)
		}
		needUpdate = true
	}

	if !gitlabServiceIsEqual(&service.Spec, &spec) {
		copyGitlabService(&service.Spec, &spec)
		needUpdate = true
	}

	if needUpdate {
		return s.updateService(ctx, service)
	}

	return nil
}

func gitlabServiceIsEqual(src, dst *corev1.ServiceSpec) bool {
	if !reflect.DeepEqual(src.Ports, dst.Ports) ||
		!reflect.DeepEqual(src.Selector, dst.Selector) {
		return false
	}
	return true
}

func copyGitlabService(src, dst *corev1.ServiceSpec) {
	src.Ports = dst.Ports
	src.Selector = dst.Selector
}

const (
	labelKeyEventSource = "eventsource-name"
)

func (s *runtimeSyncer) calculateEventSourceServiceGitlab(ctx context.Context, vars map[string]string) (*corev1.ServiceSpec, error) {
	eventSourceName, err := getStringFromTemplate(tmplEventSourceGitlab, vars)
	if err != nil {
		return nil, err
	}

	spec := &corev1.ServiceSpec{
		Ports: []corev1.ServicePort{
			{
				Protocol:   "TCP",
				Port:       eventSourcePort,
				TargetPort: intstr.FromInt(int(eventSourcePort)),
			},
		},
		Selector: map[string]string{
			labelKeyEventSource: eventSourceName,
		},
	}

	return spec, nil
}

func (s *runtimeSyncer) syncEventSourceIngressGitlab(ctx context.Context, name string, owner client.Object, spec networkv1.IngressSpec) error {
	key := types.NamespacedName{
		Namespace: s.config.EventBus.ArgoEvents.Namespace,
		Name:      name,
	}
	ingress := &networkv1.Ingress{}
	if err := s.k8sClient.Get(ctx, key, ingress); err != nil {
		if apierrors.IsNotFound(err) {
			ingress = &networkv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      key.Name,
					Namespace: key.Namespace,
				},
			}
		} else {
			return fmt.Errorf("get ingress %s failed: %w", key.Name, err)
		}
	}

	needUpdate := false
	if !nautesutil.IsOwner(owner, ingress, scheme) {
		if err := controllerutil.SetOwnerReference(owner, ingress, scheme); err != nil {
			return fmt.Errorf("can not set secret %s's owner: %w", name, err)
		}
		needUpdate = true
	}

	if !reflect.DeepEqual(ingress.Spec, spec) {
		ingress.Spec = spec
		needUpdate = true
	}

	if needUpdate {
		return s.updateIngress(ctx, ingress)
	}

	return nil
}

// calculateEventSourceIngressGitlab will create ingress spec witch eventsources need.
// If eventsources create a gitlab event A. It webhook endpoint is "/product-3853-dev-runtime-gitlab/repo-A"
// and url is "http://webhook.127.0.0.1.nip.io:32000",
// it will create a ingress host is "webhook.127.0.0.1.nip.io" and path is "/product-3853-dev-runtime-gitlab"
func (s *runtimeSyncer) calculateEventSourceIngressGitlab(ctx context.Context, vars map[string]string) (*networkv1.IngressSpec, error) {
	serviceName, err := getStringFromTemplate(tmplGitlabServiceName, vars)
	if err != nil {
		return nil, err
	}

	eventSourcePath, err := getStringFromTemplate(tmplGitlabEventSourcePath, vars)
	if err != nil {
		return nil, err
	}

	url, err := url.Parse(s.webhookURL)
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(url.Host)
	if err != nil {
		return nil, err
	}

	pathType := networkv1.PathTypeImplementationSpecific
	spec := &networkv1.IngressSpec{
		Rules: []networkv1.IngressRule{
			{
				Host: host,
				IngressRuleValue: networkv1.IngressRuleValue{
					HTTP: &networkv1.HTTPIngressRuleValue{
						Paths: []networkv1.HTTPIngressPath{
							{
								Path:     eventSourcePath,
								PathType: &pathType,
								Backend: networkv1.IngressBackend{
									Service: &networkv1.IngressServiceBackend{
										Name: serviceName,
										Port: networkv1.ServiceBackendPort{
											Number: eventSourcePort,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	return spec, nil
}

// caculateSensorGitlab will caculate a sensor by runtime trigger witch eventsource has gitlab.
func (s *runtimeSyncer) caculateSensorGitlab(ctx context.Context, runtimeTrigger nautescrd.PipelineTrigger) (*sensorv1alpha1.Sensor, error) {
	sensor := &sensorv1alpha1.Sensor{}
	eventSource, err := s.runtime.GetEventSource(runtimeTrigger.EventSource)
	if err != nil {
		return nil, err
	}

	pipeline, err := s.runtime.GetPipeline(runtimeTrigger.Pipeline)
	if err != nil {
		return nil, err
	}

	vars := copyVars(s.vars)
	vars[keyEventName] = eventSource.Name
	vars[keyEventSourceType] = string(eventTypeGitlab)
	vars[keyPipelineName] = runtimeTrigger.Pipeline
	vars[keyPipelinePath] = pipeline.Path
	vars[keyIsCodeRepoTrigger] = "true"

	dependency, err := s.caculateDependencyGitlab(ctx, *eventSource, vars)
	if err != nil {
		return nil, fmt.Errorf("get dependency failed: %w", err)
	}
	sensor.Spec.Dependencies = append(sensor.Spec.Dependencies, *dependency)

	trigger, err := s.caculateTriggerGitlab(ctx, runtimeTrigger, vars)
	if err != nil {
		return nil, fmt.Errorf("get trigger failed: %w", err)
	}
	sensor.Spec.Triggers = append(sensor.Spec.Triggers, *trigger)

	return sensor, nil
}

func (s *runtimeSyncer) caculateDependencyGitlab(ctx context.Context, event nautescrd.EventSource, vars map[string]string) (*sensorv1alpha1.EventDependency, error) {
	name, err := getStringFromTemplate(tmplDependencyName, vars)
	if err != nil {
		return nil, err
	}

	eventSourceName, err := getStringFromTemplate(tmplEventSourceGitlab, vars)
	if err != nil {
		return nil, err
	}

	eventName, err := getStringFromTemplate(tmplEventSourceGitlabEventName, vars)
	if err != nil {
		return nil, err
	}

	dependency := sensorv1alpha1.EventDependency{
		Name:            name,
		EventSourceName: eventSourceName,
		EventName:       eventName,
		Filters: &sensorv1alpha1.EventDependencyFilter{
			Data:                []sensorv1alpha1.DataFilter{},
			DataLogicalOperator: "and",
		},
	}

	if event.Gitlab.Events != nil && len(event.Gitlab.Events) != 0 {
		dependency.Filters.Data = append(dependency.Filters.Data, sensorv1alpha1.DataFilter{
			Path:  "body.event_name",
			Type:  "string",
			Value: event.Gitlab.Events,
		})
	}

	if event.Gitlab.Revision != "" {
		dependency.Filters.Script = fmt.Sprintf("if string.match(event.body.ref, \"refs\\/heads\\/%s\") then return true else return false end", event.Gitlab.Revision)
	}

	return &dependency, nil
}

func (s *runtimeSyncer) caculateTriggerGitlab(ctx context.Context, runtimeTrigger nautescrd.PipelineTrigger, vars map[string]string) (*sensorv1alpha1.Trigger, error) {
	trigger := &sensorv1alpha1.Trigger{
		Template: &sensorv1alpha1.TriggerTemplate{},
	}

	dependencyName, err := getStringFromTemplate(tmplDependencyName, vars)
	if err != nil {
		return nil, err
	}

	triggerName, err := getStringFromTemplate(tmplTriggerName, vars)
	if err != nil {
		return nil, err
	}

	trigger.Template.Conditions = dependencyName
	trigger.Template.Name = triggerName

	trigger.Template.K8s = &sensorv1alpha1.StandardK8STrigger{
		Source:     &sensorv1alpha1.ArtifactLocation{},
		Operation:  "create",
		Parameters: []sensorv1alpha1.TriggerParameter{},
	}

	paras, err := caculateParameterGitlab(ctx, runtimeTrigger, vars)
	if err != nil {
		return nil, err
	}
	trigger.Template.K8s.Parameters = paras

	initPipeline, err := getStringFromTemplate(tmplTektonInitPipeline, vars)
	if err != nil {
		return nil, err
	}
	resource := common.NewResource(initPipeline)
	trigger.Template.K8s.Source = &sensorv1alpha1.ArtifactLocation{
		Resource: &resource,
	}

	return trigger, nil
}

// caculateParameterGitlab will return template k8s parameters based on trigger.
// If trigger Revision is empty, runtime will use eventsource ref as pipeline ref, else it will use trigger.Revision.
func caculateParameterGitlab(ctx context.Context, runtimeTrigger nautescrd.PipelineTrigger, vars map[string]string) ([]sensorv1alpha1.TriggerParameter, error) {
	dependencyName, err := getStringFromTemplate(tmplDependencyName, vars)
	if err != nil {
		return nil, err
	}

	paras := []sensorv1alpha1.TriggerParameter{}
	pipelineBranch := sensorv1alpha1.TriggerParameter{
		Dest: "spec.params.0.value",
		Src:  &sensorv1alpha1.TriggerParameterSource{},
	}
	if runtimeTrigger.Revision != "" {
		pipelineBranch.Src.Value = &runtimeTrigger.Revision
	} else {
		pipelineBranch.Src.DependencyName = dependencyName
		pipelineBranch.Src.DataKey = "body.ref"
	}
	paras = append(paras, pipelineBranch)

	sourceBranch := sensorv1alpha1.TriggerParameter{
		Dest: "spec.params.1.value",
		Src: &sensorv1alpha1.TriggerParameterSource{
			DependencyName: dependencyName,
			DataKey:        "body.ref",
		},
	}
	paras = append(paras, sourceBranch)

	return paras, nil
}
