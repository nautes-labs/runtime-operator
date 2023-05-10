// Copyright 2023 Nautes Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controllers

import (
	"context"
	"fmt"
	"time"

	nautescrd "github.com/nautes-labs/pkg/api/v1alpha1"
	nautescfg "github.com/nautes-labs/pkg/pkg/nautesconfigs"
	secprovider "github.com/nautes-labs/runtime-operator/internal/secret/provider"
	runtimecontext "github.com/nautes-labs/runtime-operator/pkg/context"
	interfaces "github.com/nautes-labs/runtime-operator/pkg/interface"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// ProjectPipelineRuntimeReconciler reconciles a ProjectPipelineRuntime object
type ProjectPipelineRuntimeReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	Syncer       interfaces.RuntimeSyncer
	NautesConfig nautescfg.NautesConfigs
}

//+kubebuilder:rbac:groups=nautes.resource.nautes.io,resources=projectpipelineruntimes,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=nautes.resource.nautes.io,resources=projectpipelineruntimes/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=nautes.resource.nautes.io,resources=projectpipelineruntimes/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the ProjectPipelineRuntime object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.11.0/pkg/reconcile
func (r *ProjectPipelineRuntimeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	runtime := &nautescrd.ProjectPipelineRuntime{}
	err := r.Client.Get(ctx, req.NamespacedName, runtime)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	cfg, err := r.NautesConfig.GetConfigByClient(r.Client)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("get nautes config failed: %w", err)
	}
	ctx = runtimecontext.NewNautesConfigContext(ctx, *cfg)

	secClient, err := secprovider.GetSecretClient(ctx)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("get secret provider failed: %w", err)
	}
	ctx = runtimecontext.NewSecretClientContext(ctx, secClient)
	defer secClient.Logout()

	if !runtime.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(runtime, runtimeFinalizerName) {
			return ctrl.Result{}, nil
		}

		if err := r.Syncer.Delete(ctx, runtime); err != nil {
			setPipelineRuntimeStatus(runtime, nil, err)
			if err := r.Status().Update(ctx, runtime); err != nil {
				logger.Error(err, "update status failed")
			}
			return ctrl.Result{}, err
		}

		controllerutil.RemoveFinalizer(runtime, runtimeFinalizerName)
		if err := r.Update(ctx, runtime); err != nil {
			return ctrl.Result{}, err
		}
		logger.V(1).Info("delete finish")
		return ctrl.Result{RequeueAfter: time.Second * 60}, err
	}

	controllerutil.AddFinalizer(runtime, runtimeFinalizerName)
	if err := r.Update(ctx, runtime); err != nil {
		return ctrl.Result{}, err
	}

	deployInfo, err := r.Syncer.Sync(ctx, runtime)
	setPipelineRuntimeStatus(runtime, deployInfo, err)

	if err := r.Status().Update(ctx, runtime); err != nil {
		return ctrl.Result{}, err
	}
	logger.V(1).Info("reconcile finish")

	return ctrl.Result{RequeueAfter: time.Second * 60}, err
}

// SetupWithManager sets up the controller with the Manager.
func (r *ProjectPipelineRuntimeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&nautescrd.ProjectPipelineRuntime{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}

func setPipelineRuntimeStatus(runtime *nautescrd.ProjectPipelineRuntime, result *interfaces.DeployInfo, err error) {
	if err != nil {
		condition := metav1.Condition{
			Type:    runtimeConditionType,
			Status:  "False",
			Reason:  runtimeConditionReason,
			Message: err.Error(),
		}
		runtime.Status.Conditions = nautescrd.GetNewConditions(runtime.Status.Conditions, []metav1.Condition{condition}, map[string]bool{runtimeConditionType: true})
	} else {
		condition := metav1.Condition{
			Type:   runtimeConditionType,
			Status: "True",
			Reason: runtimeConditionReason,
		}
		runtime.Status.Conditions = nautescrd.GetNewConditions(runtime.Status.Conditions, []metav1.Condition{condition}, map[string]bool{runtimeConditionType: true})
	}
}
