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

type SecretClient interface {
	Cluster
	Git
	Secret
	Auth
	Logout() error
}

type Auth interface {
	GetRole(ctx context.Context, authName string, role Role) (*Role, error)
	CreateRole(ctx context.Context, authName string, role Role) error
	DeleteRole(ctx context.Context, authName string, role Role) error
}

type Cluster interface {
	GetAccessInfo(ctx context.Context, clusterName string) (string, error)
}

type Git interface {
	GrantPermission(ctx context.Context, providerType, repoName, destUser, destEnv string) error
	RevokePermission(ctx context.Context, providerType, repoName, destUser, destEnv string) error
}

type Secret interface {
	GetSecretDatabaseName(ctx context.Context, repo SecretInfo) (string, error)
	GetSecretKey(ctx context.Context, repo SecretInfo) (string, error)
}

type Role struct {
	Name   string
	Users  []string
	Groups []string
}

type SecretType int32

const (
	SECRET_TYPE_GIT      = 1
	SECRET_TYPE_ARTIFACT = 2
	SECRET_TYPE_CLUSTER  = 3
	SECRET_TYPE_TENANT   = 4
)

type SecretInfo struct {
	Type          SecretType
	CodeRepo      *CodeRepo
	AritifaceRepo *ArifactRepo
}

type CodeRepo struct {
	ProviderType string
	ID           string
	User         string
	Permission   string
}

type ArifactRepo struct {
	ProviderName string
	RepoType     string
	ID           string
	User         string
	Permission   string
}
