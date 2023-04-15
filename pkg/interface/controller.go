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

import (
	"context"

	nautescrd "github.com/nautes-labs/pkg/api/v1alpha1"
	nautescfg "github.com/nautes-labs/pkg/pkg/nautesconfigs"
)

type DeploymentRuntimeSyncer interface {
	Sync(ctx context.Context, runtime nautescrd.DeploymentRuntime) (*DeployInfo, error)
	Delete(ctx context.Context, runtime nautescrd.DeploymentRuntime) error
}

type DeployTask struct {
	AccessInfo  AccessInfo
	Product     nautescrd.Product
	NautesCfg   nautescfg.Config
	Runtime     Runtime
	RuntimeType RuntimeType
}

func (t *DeployTask) GetLabel() map[string]string {
	return map[string]string{nautescrd.LABEL_BELONG_TO_PRODUCT: t.Product.Name}
}
