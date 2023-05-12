package argoevents

import (
	"context"
	"fmt"

	"github.com/argoproj/argo-events/pkg/apis/common"
	eventsourcev1alpha1 "github.com/argoproj/argo-events/pkg/apis/eventsource/v1alpha1"
	sensorv1alpha1 "github.com/argoproj/argo-events/pkg/apis/sensor/v1alpha1"
	nautescrd "github.com/nautes-labs/pkg/api/v1alpha1"
)

func (s *runtimeSyncer) syncEventSourceCalendar(ctx context.Context) error {
	eventSourceName, err := getStringFromTemplate(tmplEventSourceCalendar, s.vars)
	if err != nil {
		return err
	}

	spec, err := s.calculateEventSourceCalendar(ctx, s.runtime.Spec.EventSources)
	if err != nil {
		return fmt.Errorf("sync gitlab event source failed: %w", err)
	}
	if spec == nil {
		return s.deleteEventSource(ctx, eventSourceName)
	}

	if err = s.syncEventSource(ctx, eventSourceName, *spec); err != nil {
		return fmt.Errorf("create or update event source %s failed: %w", eventSourceName, err)
	}
	return nil
}

func (s *runtimeSyncer) deleteEventSourceCalendar(ctx context.Context) error {
	eventSourceName, err := getStringFromTemplate(tmplEventSourceCalendar, s.vars)
	if err != nil {
		return err
	}

	return s.deleteEventSource(ctx, eventSourceName)
}

func (s *runtimeSyncer) calculateEventSourceCalendar(ctx context.Context, eventSources []nautescrd.EventSource) (*eventsourcev1alpha1.EventSourceSpec, error) {
	eventSourceSpec := &eventsourcev1alpha1.EventSourceSpec{
		Calendar: map[string]eventsourcev1alpha1.CalendarEventSource{},
	}

	for _, evsrc := range s.runtime.Spec.EventSources {
		if evsrc.Calendar == nil {
			continue
		}

		eventName, err := getStringFromTemplate(tmplEventSourceCalendarEventName, map[string]string{"eventName": evsrc.Name})
		if err != nil {
			return nil, err
		}

		eventSourceSpec.Calendar[eventName] = eventsourcev1alpha1.CalendarEventSource{
			Schedule:       evsrc.Calendar.Schedule,
			Interval:       evsrc.Calendar.Interval,
			ExclusionDates: evsrc.Calendar.ExclusionDates,
			Timezone:       evsrc.Calendar.Timezone,
		}
	}

	if len(eventSourceSpec.Calendar) == 0 {
		return nil, nil
	}
	return eventSourceSpec, nil
}

func (s *runtimeSyncer) caculateSensorCalendar(ctx context.Context, runtimeTrigger nautescrd.PipelineTrigger) (*sensorv1alpha1.Sensor, error) {
	sensor := &sensorv1alpha1.Sensor{}
	eventSource, err := s.runtime.GetEventSource(runtimeTrigger.EventSource)
	if err != nil {
		return nil, err
	}

	pipeline, err := s.runtime.GetPipeline(runtimeTrigger.Pipeline)
	if err != nil {
		return nil, err
	}

	vars := deepCopyStringMap(s.vars)
	vars[keyEventName] = eventSource.Name
	vars[keyEventSourceType] = string(eventTypeCalendar)
	vars[keyPipelineName] = runtimeTrigger.Pipeline
	vars[keyPipelinePath] = pipeline.Path
	vars[keyIsCodeRepoTrigger] = "false"

	dependency, err := s.caculateDependencyCalendar(ctx, *eventSource, vars)
	if err != nil {
		return nil, fmt.Errorf("get dependency failed: %w", err)
	}
	sensor.Spec.Dependencies = append(sensor.Spec.Dependencies, *dependency)

	trigger, err := s.caculateTriggerCalendar(ctx, runtimeTrigger, vars)
	if err != nil {
		return nil, fmt.Errorf("get trigger failed: %w", err)
	}
	sensor.Spec.Triggers = append(sensor.Spec.Triggers, *trigger)
	return sensor, nil
}

func (s *runtimeSyncer) caculateDependencyCalendar(ctx context.Context, event nautescrd.EventSource, vars map[string]string) (*sensorv1alpha1.EventDependency, error) {
	name, err := getStringFromTemplate(tmplDependencyName, vars)
	if err != nil {
		return nil, err
	}

	eventSourceName, err := getStringFromTemplate(tmplEventSourceCalendar, vars)
	if err != nil {
		return nil, err
	}

	eventName, err := getStringFromTemplate(tmplEventSourceCalendarEventName, vars)
	if err != nil {
		return nil, err
	}

	dependency := sensorv1alpha1.EventDependency{
		Name:            name,
		EventSourceName: eventSourceName,
		EventName:       eventName,
	}

	return &dependency, nil
}

func (s *runtimeSyncer) caculateTriggerCalendar(ctx context.Context, runtimeTrigger nautescrd.PipelineTrigger, vars map[string]string) (*sensorv1alpha1.Trigger, error) {
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

	paras, err := caculateParameterCalendar(ctx, runtimeTrigger, vars)
	if err != nil {
		return nil, err
	}
	trigger.Template.K8s.Parameters = paras

	intiPipeline, err := getStringFromTemplate(tmplTektonInitPipeline, vars)
	if err != nil {
		return nil, err
	}
	resource := common.NewResource(intiPipeline)
	trigger.Template.K8s.Source = &sensorv1alpha1.ArtifactLocation{
		Resource: &resource,
	}

	return trigger, nil
}

func caculateParameterCalendar(ctx context.Context, runtimeTrigger nautescrd.PipelineTrigger, vars map[string]string) ([]sensorv1alpha1.TriggerParameter, error) {
	paras := []sensorv1alpha1.TriggerParameter{}

	if runtimeTrigger.Revision != "" {
		pipelineBranch := sensorv1alpha1.TriggerParameter{
			Src: &sensorv1alpha1.TriggerParameterSource{
				Value: &runtimeTrigger.Revision,
			},
			Dest: "spec.params.0.value",
		}

		paras = append(paras, pipelineBranch)
	}

	return paras, nil
}
