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
	"fmt"

	nautescrd "github.com/nautes-labs/pkg/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// IsLegal used to check resources is available for reconcile
func IsLegal(res client.Object, productName string) (string, bool) {
	if !res.GetDeletionTimestamp().IsZero() {
		return fmt.Sprintf("resouce %s is terminating", res.GetName()), false
	}

	if !IsBelongsToProduct(res, productName) {
		return fmt.Sprintf("resource %s is not belongs to product", res.GetName()), false
	}
	return "", true
}

// IsBelongsToProduct check resouces is maintain by nautes
func IsBelongsToProduct(res client.Object, productName string) bool {
	labels := res.GetLabels()
	name, ok := labels[nautescrd.LABEL_BELONG_TO_PRODUCT]
	if !ok || name != productName {
		return false
	}
	return true
}
