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

package utils

import (
	"context"
	"fmt"

	nautescrd "github.com/nautes-labs/pkg/api/v1alpha1"
	interfaces "github.com/nautes-labs/runtime-operator/pkg/interface"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func getEnvClusterMapping(ctx context.Context, k8sClient client.Client, runtimes []interfaces.Runtime) (map[string]string, error) {
	envClusterMap := map[string]string{}
	for _, runtime := range runtimes {
		envName := runtime.GetDestination()

		if _, ok := envClusterMap[envName]; !ok {
			env := &nautescrd.Environment{}
			key := types.NamespacedName{
				Namespace: runtime.GetProduct(),
				Name:      envName,
			}
			if err := k8sClient.Get(ctx, key, env); err != nil {
				return nil, err
			}
			envClusterMap[envName] = env.Spec.Cluster
		}
	}
	return envClusterMap, nil
}

func getRuntimesInProduct(ctx context.Context, k8sClient client.Client, product string) ([]interfaces.Runtime, error) {
	deploymentRuntimeList := &nautescrd.DeploymentRuntimeList{}
	listOpt := client.InNamespace(product)
	if err := k8sClient.List(ctx, deploymentRuntimeList, &listOpt); err != nil {
		return nil, err
	}

	pipelineRuntimeList := &nautescrd.ProjectPipelineRuntimeList{}
	if err := k8sClient.List(ctx, pipelineRuntimeList, &listOpt); err != nil {
		return nil, err
	}

	runtimes := []interfaces.Runtime{}
	for _, runtime := range deploymentRuntimeList.Items {
		if !runtime.DeletionTimestamp.IsZero() {
			continue
		}
		runtimes = append(runtimes, runtime.DeepCopy())
	}

	for _, runtime := range pipelineRuntimeList.Items {
		if !runtime.DeletionTimestamp.IsZero() {
			continue
		}
		runtimes = append(runtimes, runtime.DeepCopy())
	}

	return runtimes, nil
}

func GetProductNamespacesInCluster(ctx context.Context, k8sClient client.Client, product, cluster string) ([]string, error) {
	runtimes, err := getRuntimesInProduct(ctx, k8sClient, product)
	if err != nil {
		return nil, err
	}

	envClusterMap, err := getEnvClusterMapping(ctx, k8sClient, runtimes)
	if err != nil {
		return nil, err
	}

	namespacesMap := map[string]bool{}
	for _, runtime := range runtimes {
		envName := runtime.GetDestination()

		clusterName, ok := envClusterMap[envName]
		if !ok || clusterName != cluster {
			continue
		}

		for _, namespace := range runtime.GetNamespaces() {
			namespacesMap[namespace] = true
		}
	}

	namespaces := []string{}
	for namespace := range namespacesMap {
		namespaces = append(namespaces, namespace)
	}

	namespaces = append(namespaces, product)

	return namespaces, nil
}

func GetURLsInCluster(ctx context.Context, k8sClient client.Client, product, cluster string, nautesNamespace string) ([]string, error) {
	runtimes, err := getRuntimesInProduct(ctx, k8sClient, product)
	if err != nil {
		return nil, err
	}

	envClusterMap, err := getEnvClusterMapping(ctx, k8sClient, runtimes)
	if err != nil {
		return nil, err
	}

	urlsMap := map[string]bool{}
	for _, runtime := range runtimes {
		deployRuntime, ok := runtime.(*nautescrd.DeploymentRuntime)
		if !ok {
			return nil, fmt.Errorf("runtime is not a deployment runtime")
		}
		envName := runtime.GetDestination()

		clusterName, ok := envClusterMap[envName]
		if !ok || clusterName != cluster {
			continue
		}

		codeRepo := &nautescrd.CodeRepo{}
		key := types.NamespacedName{
			Namespace: product,
			Name:      deployRuntime.Spec.ManifestSource.CodeRepo,
		}
		if err := k8sClient.Get(ctx, key, codeRepo); err != nil {
			return nil, err
		}
		url, err := GetCodeRepoURL(ctx, k8sClient, *codeRepo, nautesNamespace)
		if err != nil {
			return nil, err
		}

		urlsMap[url] = true
	}

	urls := []string{}
	for url := range urlsMap {
		urls = append(urls, url)
	}
	return urls, nil
}
