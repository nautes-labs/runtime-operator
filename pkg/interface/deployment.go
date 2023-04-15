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

package interfaces

import "context"

// nautescrd "github.com/nautes-labs/pkg/api/v1alpha1"

const (
	RUNTIME_TYPE_DEPLOYMENT = 1
	RUNTIME_TYPE_PIPELINE   = 2
)

type RuntimeType int

type Deployment interface {
	Deploy(ctx context.Context, task DeployTask) (*DeployInfo, error)
	UnDeploy(ctx context.Context, task DeployTask) error
}

type DeployInfo struct {
	Source string
}
