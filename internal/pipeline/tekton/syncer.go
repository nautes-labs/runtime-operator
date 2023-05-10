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

package tekton

import (
	"context"

	interfaces "github.com/nautes-labs/runtime-operator/pkg/interface"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type syncer struct {
	kubernetesClient client.Client
}

func NewSyncer(client client.Client) interfaces.Pipeline {
	return syncer{
		kubernetesClient: client,
	}
}

func (s syncer) DeployPipelineRuntime(ctx context.Context, task interfaces.RuntimeSyncTask) error {
	return nil
}

func (s syncer) UnDeployPipelineRuntime(ctx context.Context, task interfaces.RuntimeSyncTask) error {
	return nil
}
