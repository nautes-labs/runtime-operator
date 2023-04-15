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

package deploymentruntime

import (
	"context"
	"fmt"

	nautescrd "github.com/nautes-labs/pkg/api/v1alpha1"
	nautescfg "github.com/nautes-labs/pkg/pkg/nautesconfigs"
	runtimecontext "github.com/nautes-labs/runtime-operator/pkg/context"
	interfaces "github.com/nautes-labs/runtime-operator/pkg/interface"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

func init() {
	DeployApps = make(map[nautescfg.DeployAppType]interfaces.Deployment)
	EnvManagers = make(map[nautescrd.ClusterKind]interfaces.EnvManager)
}

var (
	DeployApps  map[nautescfg.DeployAppType]interfaces.Deployment
	EnvManagers map[nautescrd.ClusterKind]interfaces.EnvManager
)

type Syncer struct {
	Client client.Client
}

// Sync will build up runtime in destination
func (s *Syncer) Sync(ctx context.Context, runtime nautescrd.DeploymentRuntime) (*interfaces.DeployInfo, error) {
	cfg, ok := runtimecontext.FromNautesConfigContext(ctx)
	if !ok {
		return nil, fmt.Errorf("get nautes config from context failed")
	}

	envManager, deployApp, cluster, err := s.getDeployInfo(ctx, &runtime)
	if err != nil {
		return nil, err
	}

	accessInfo, err := envManager.GetAccessInfo(ctx, *cluster)
	if err != nil {
		return nil, fmt.Errorf("get access info failed: %w", err)
	}

	deployTask, err := s.createDeployTask(cfg, *accessInfo, &runtime)
	if err != nil {
		return nil, fmt.Errorf("create deploy task failed: %w", err)
	}

	_, err = envManager.Sync(ctx, *deployTask)
	if err != nil {
		return nil, fmt.Errorf("init env failed: %w", err)
	}

	deployInfo, err := deployApp.Deploy(ctx, *deployTask)
	if err != nil {
		return nil, fmt.Errorf("deploy app failed: %w", err)
	}

	return deployInfo, nil
}

// Delete will clean up runtime in destination
func (s *Syncer) Delete(ctx context.Context, runtime nautescrd.DeploymentRuntime) error {
	cfg, ok := runtimecontext.FromNautesConfigContext(ctx)
	if !ok {
		return fmt.Errorf("get nautes config from context failed")
	}

	envManager, deployApp, cluster, err := s.getDeployInfo(ctx, &runtime)
	if err != nil {
		return err
	}

	accessInfo, err := envManager.GetAccessInfo(ctx, *cluster)
	if err != nil {
		return fmt.Errorf("get access info failed: %w", err)
	}

	deployTask, err := s.createDeployTask(cfg, *accessInfo, &runtime)
	if err != nil {
		return fmt.Errorf("create deploy task failed: %w", err)
	}

	err = deployApp.UnDeploy(ctx, *deployTask)
	if err != nil {
		return fmt.Errorf("remove app failed: %w", err)
	}

	err = envManager.Remove(ctx, *deployTask)
	if err != nil {
		return fmt.Errorf("remove env failed: %w", err)
	}

	return nil
}

func (s *Syncer) getDeployInfo(ctx context.Context, runtime *nautescrd.DeploymentRuntime) (interfaces.EnvManager, interfaces.Deployment, *nautescrd.Cluster, error) {
	cfg, ok := runtimecontext.FromNautesConfigContext(ctx)
	if !ok {
		return nil, nil, nil, fmt.Errorf("can not get nautes config from context")
	}

	cluster, err := s.getCluster(ctx, runtime.GetProduct(), runtime.Spec.Destination)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get cluster info failed: %w", err)
	}

	envManager, ok := EnvManagers[cluster.Spec.ClusterKind]
	if !ok {
		return nil, nil, nil, fmt.Errorf("cluster provider %s is not support", cluster.Spec.ClusterKind)
	}

	deployAppType, ok := cfg.Deploy.DefaultDeployApp[string(cluster.Spec.ClusterKind)]
	if !ok {
		return nil, nil, nil, fmt.Errorf("unknow deployment type %s", cluster.Spec.ClusterKind)
	}
	deployApp, ok := DeployApps[deployAppType]
	if !ok {
		return nil, nil, nil, fmt.Errorf("deployment type %s is not support", deployAppType)
	}

	return envManager, deployApp, cluster, nil
}

func (s *Syncer) getCluster(ctx context.Context, productName, name string) (*nautescrd.Cluster, error) {
	cfg, ok := runtimecontext.FromNautesConfigContext(ctx)
	if !ok {
		return nil, fmt.Errorf("can not get nautes config from context")
	}

	env := &nautescrd.Environment{}
	key := types.NamespacedName{
		Namespace: productName,
		Name:      name,
	}

	if err := s.Client.Get(ctx, key, env); err != nil {
		return nil, err
	}

	cluster := &nautescrd.Cluster{}
	key = types.NamespacedName{
		Namespace: cfg.Nautes.Namespace,
		Name:      env.Spec.Cluster,
	}
	if err := s.Client.Get(ctx, key, cluster); err != nil {
		return nil, err
	}

	return cluster, nil
}

func (s *Syncer) createDeployTask(cfg nautescfg.Config, assessInfo interfaces.AccessInfo, runtime interfaces.Runtime) (*interfaces.DeployTask, error) {
	product := &nautescrd.Product{}
	key := types.NamespacedName{
		Namespace: cfg.Nautes.Namespace,
		Name:      runtime.GetProduct(),
	}
	if err := s.Client.Get(context.TODO(), key, product); err != nil {
		return nil, err
	}

	var runtimeType interfaces.RuntimeType
	switch runtime.(type) {
	case *nautescrd.DeploymentRuntime:
		runtimeType = interfaces.RUNTIME_TYPE_DEPLOYMENT
	case *nautescrd.ProjectPipelineRuntime:
		runtimeType = interfaces.RUNTIME_TYPE_PIPELINE
	default:
		return nil, fmt.Errorf("unknow runtime type")
	}

	task := &interfaces.DeployTask{
		AccessInfo:  assessInfo,
		Product:     *product,
		NautesCfg:   cfg,
		Runtime:     runtime,
		RuntimeType: runtimeType,
	}

	return task, nil
}
