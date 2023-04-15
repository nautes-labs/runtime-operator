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

package kubernetes

import (
	"context"
	"fmt"

	nautescrd "github.com/nautes-labs/pkg/api/v1alpha1"
	"github.com/nautes-labs/pkg/pkg/kubeconvert"
	interfaces "github.com/nautes-labs/runtime-operator/pkg/interface"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	runtimecontext "github.com/nautes-labs/runtime-operator/pkg/context"
)

type Syncer struct {
	client.Client
}

// GetAccessInfo get connect info from cluster resource
func (m Syncer) GetAccessInfo(ctx context.Context, cluster nautescrd.Cluster) (*interfaces.AccessInfo, error) {
	secClient, ok := runtimecontext.FromSecretClientConetxt(ctx)
	if !ok {
		return nil, fmt.Errorf("get secret client from context failed")
	}

	accessInfo, err := secClient.GetAccessInfo(ctx, cluster.Name)
	if err != nil {
		return nil, fmt.Errorf("get access info failed: %w", err)
	}

	restConfig, err := kubeconvert.ConvertStringToRestConfig(accessInfo)
	if err != nil {
		return nil, fmt.Errorf("get access info failed: %w", err)
	}

	return &interfaces.AccessInfo{
		Name:       cluster.Name,
		Type:       interfaces.ACCESS_TYPE_K8S,
		Kubernetes: restConfig,
	}, nil
}

// Sync create or update a usable env for the next step, it will create namespaces, rolebinding and other resources runtime required.
func (m Syncer) Sync(ctx context.Context, task interfaces.DeployTask) (*interfaces.EnvSyncResult, error) {
	destCluster, err := newDestCluster(ctx, task)
	if err != nil {
		return nil, fmt.Errorf("create dest cluster client failed: %w", err)
	}

	if err := destCluster.syncProductNamespace(ctx); err != nil {
		return nil, fmt.Errorf("sync product namespace failed: %w", err)
	}

	if err := destCluster.syncProductAuthority(ctx); err != nil {
		return nil, fmt.Errorf("sync product authority failed: %w", err)
	}

	if err := destCluster.syncRuntimeNamespace(ctx); err != nil {
		return nil, fmt.Errorf("sync runtime namespace failed: %w", err)
	}

	if err := destCluster.syncRelationShip(ctx); err != nil {
		return nil, fmt.Errorf("sync relationship namespace failed: %w", err)
	}

	if err := destCluster.SyncRole(ctx); err != nil {
		return nil, fmt.Errorf("sync role failed: %w", err)
	}

	syncResult := &interfaces.EnvSyncResult{}
	switch task.RuntimeType {
	case interfaces.RUNTIME_TYPE_DEPLOYMENT:
		repos, err := m.getRepos(ctx, task)
		if err != nil {
			syncResult.Error = err
			break
		}

		err = destCluster.SyncRepo(ctx, repos)
		if err != nil {
			syncResult.Error = err
			break
		}

	}

	return syncResult, nil
}

// Remove will cleaa up resouces Sync create.
func (m Syncer) Remove(ctx context.Context, task interfaces.DeployTask) error {
	logger := log.FromContext(ctx)

	destCluster, err := newDestCluster(ctx, task)
	if err != nil {
		return fmt.Errorf("create dest cluster client failed: %w", err)
	}

	if err := destCluster.DeleteRole(ctx); err != nil {
		return fmt.Errorf("delete role failed: %w", err)
	}

	if err := destCluster.deleteNamespace(ctx); err != nil {
		return fmt.Errorf("delete runtime namespace failed: %w", err)
	}

	deletable, err := destCluster.checkProductNamespaceIsUsing(ctx)
	if err != nil {
		return fmt.Errorf("check product namespace is using failed: %w", err)
	}
	if deletable {
		logger.V(1).Info("threre are no namespace under product namespace , it will be delete", "NamespaceName", task.Product.Name)
		if err := destCluster.deleteProductNamespace(ctx); err != nil {
			return fmt.Errorf("delete product namespace failed: %w", err)
		}
	}

	return nil
}

func (m Syncer) getRepos(ctx context.Context, task interfaces.DeployTask) ([]interfaces.SecretInfo, error) {
	artifactRepos := &nautescrd.ArtifactRepoList{}
	listOpts := []client.ListOption{
		client.InNamespace(task.Product.Name),
	}
	if err := m.Client.List(ctx, artifactRepos, listOpts...); err != nil {
		return nil, fmt.Errorf("get repo list failed: %w", err)
	}

	repos := []interfaces.SecretInfo{}
	for _, artifactRepo := range artifactRepos.Items {
		provider := &nautescrd.ArtifactRepoProvider{}
		key := types.NamespacedName{
			Namespace: task.NautesCfg.Nautes.Namespace,
			Name:      artifactRepo.Spec.ArtifactRepoProvider,
		}
		if err := m.Get(ctx, key, provider); err != nil {
			return nil, fmt.Errorf("get artifact provider failed: %w", err)
		}

		repos = append(repos, interfaces.SecretInfo{
			Type: interfaces.SECRET_TYPE_ARTIFACT,
			AritifaceRepo: &interfaces.ArifactRepo{
				ProviderName: provider.Name,
				RepoType:     provider.Spec.ProviderType,
				ID:           artifactRepo.Name,
				User:         "default",
				Permission:   "readonly",
			},
		})
	}

	return repos, nil
}
