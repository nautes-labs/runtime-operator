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

package vault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	kratos "github.com/go-kratos/kratos/v2/transport/http"
	vault "github.com/hashicorp/vault/api"
	kubernetesauth "github.com/hashicorp/vault/api/auth/kubernetes"
	configs "github.com/nautes-labs/pkg/pkg/nautesconfigs"
	nautescfg "github.com/nautes-labs/pkg/pkg/nautesconfigs"
	vaultproxy "github.com/nautes-labs/runtime-operator/internal/vaultproxy"
	runtimeinterface "github.com/nautes-labs/runtime-operator/pkg/interface"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	CLUSTER_NAMESPACE         = "cluster"
	CLUSTER_PATH              = "kubernetes/%s/default/admin"
	CLUSTER_KUBECONFIG_KEY    = "kubeconfig"
	_RUNTIME_OPERATOR_NAME    = "Runtime"
	_GIT_REPO_USER_NAME       = "default"
	_GIT_REPO_PERMISSION      = "readonly"
	_ARTIFACT_REPO_USER_NAME  = "default"
	_ARTIFACT_REPO_PERMISSION = "readonly"
)

type Vault struct {
	client *vault.Client
	vaultproxy.SecretHTTPClient
	vaultproxy.AuthHTTPClient
	vaultproxy.AuthGrantHTTPClient
	getDBName  map[runtimeinterface.SecretType]string
	getKeyFunc map[runtimeinterface.SecretType]getSecretKey
}

// CreateRole implements interfaces.SecretClient
func (s *Vault) CreateRole(ctx context.Context, clusterName string, role runtimeinterface.Role) error {
	req := &vaultproxy.AuthroleRequest{
		ClusterName: clusterName,
		DestUser:    role.Name,
		Role: &vaultproxy.AuthroleRequest_K8S{
			K8S: &vaultproxy.KubernetesAuthRoleMeta{
				Namespaces:      role.Groups[0],
				ServiceAccounts: role.Users[0],
			},
		},
	}

	if _, err := s.AuthHTTPClient.CreateAuthrole(ctx, req); err != nil {
		return err
	}
	return nil
}

// DeleteRole implements interfaces.SecretClient
func (s *Vault) DeleteRole(ctx context.Context, clusterName string, role runtimeinterface.Role) error {
	req := &vaultproxy.AuthroleRequest{
		ClusterName: clusterName,
		DestUser:    role.Name,
		Role: &vaultproxy.AuthroleRequest_K8S{
			K8S: &vaultproxy.KubernetesAuthRoleMeta{
				Namespaces:      role.Groups[0],
				ServiceAccounts: role.Users[0],
			},
		},
	}

	if _, err := s.AuthHTTPClient.DeleteAuthrole(ctx, req); err != nil {
		return err
	}
	return nil
}

// GetRole implements interfaces.SecretClient
func (s *Vault) GetRole(ctx context.Context, clusterName string, role runtimeinterface.Role) (*runtimeinterface.Role, error) {
	path := fmt.Sprintf("auth/%s/role/%s", clusterName, role.Name)
	roleInfo, err := s.client.Logical().Read(path)
	if err != nil {
		return nil, err
	}
	if roleInfo == nil {
		return nil, nil
	}

	users := roleInfo.Data["bound_service_account_names"].([]interface{})
	vaultRole := &runtimeinterface.Role{
		Name:   role.Name,
		Users:  []string{users[0].(string)},
		Groups: []string{},
	}
	return vaultRole, nil
}

// GetSecretDatabaseName implements interfaces.SecretClient
func (s *Vault) GetSecretDatabaseName(ctx context.Context, repo runtimeinterface.SecretInfo) (string, error) {
	dbName, ok := s.getDBName[repo.Type]
	if !ok {
		return "", fmt.Errorf("unknow type of secret")
	}
	return dbName, nil
}

// GetSecretKey implements interfaces.SecretClient
func (s *Vault) GetSecretKey(ctx context.Context, repo runtimeinterface.SecretInfo) (string, error) {
	fn, ok := s.getKeyFunc[repo.Type]
	if !ok {
		return "", fmt.Errorf("unknow type of secret")
	}
	return fn(ctx, repo)
}

type getSecretKey func(ctx context.Context, repo runtimeinterface.SecretInfo) (string, error)

func (s *Vault) getGitSecretKey(ctx context.Context, repo runtimeinterface.SecretInfo) (string, error) {
	meta := &vaultproxy.GitMeta{
		ProviderType: repo.CodeRepo.ProviderType,
		Id:           repo.CodeRepo.ID,
		Username:     _GIT_REPO_USER_NAME,
		Permission:   _GIT_REPO_PERMISSION,
	}
	secretMeta, err := meta.GetNames()
	if err != nil {
		return "", err
	}
	return secretMeta.SecretPath, nil
}

func (s *Vault) getArtifactSecretKey(ctx context.Context, repo runtimeinterface.SecretInfo) (string, error) {
	meta := vaultproxy.RepoMeta{
		ProviderId: repo.AritifaceRepo.ProviderName,
		Type:       repo.AritifaceRepo.RepoType,
		Id:         repo.AritifaceRepo.ID,
		Username:   _ARTIFACT_REPO_USER_NAME,
		Permission: _ARTIFACT_REPO_PERMISSION,
	}
	secretMeta, err := meta.GetNames()
	if err != nil {
		return "", err
	}
	return secretMeta.SecretPath, nil
}

func (s *Vault) GrantPermission(ctx context.Context, providerType, repoName, destUser, destEnv string) error {
	req := &vaultproxy.AuthroleGitPolicyRequest{
		ClusterName: destEnv,
		DestUser:    destUser,
		Secret: &vaultproxy.GitMeta{
			ProviderType: providerType,
			Id:           repoName,
			Username:     _GIT_REPO_USER_NAME,
			Permission:   _GIT_REPO_PERMISSION,
		},
	}
	_, err := s.GrantAuthroleGitPolicy(ctx, req)
	return err
}

func (s *Vault) RevokePermission(ctx context.Context, providerType, repoName, destUser, destEnv string) error {
	req := &vaultproxy.AuthroleGitPolicyRequest{
		ClusterName: destEnv,
		DestUser:    destUser,
		Secret: &vaultproxy.GitMeta{
			ProviderType: providerType,
			Id:           repoName,
			Username:     _GIT_REPO_USER_NAME,
			Permission:   _GIT_REPO_PERMISSION,
		},
	}
	_, err := s.RevokeAuthroleGitPolicy(ctx, req)
	return err
}
func NewClient(cfg nautescfg.SecretRepo) (runtimeinterface.SecretClient, error) {
	vaultClient, err := newVaultClient(cfg)
	if err != nil {
		return nil, err
	}
	secClient, authClient, grantClient, err := newVProxyClient(cfg.Vault.ProxyAddr, cfg.Vault.PKIPath)
	if err != nil {
		return nil, err
	}

	client := &Vault{
		client:              vaultClient,
		SecretHTTPClient:    secClient,
		AuthHTTPClient:      authClient,
		AuthGrantHTTPClient: grantClient,
	}

	client.getDBName = map[runtimeinterface.SecretType]string{
		runtimeinterface.SECRET_TYPE_GIT:      "git",
		runtimeinterface.SECRET_TYPE_ARTIFACT: "repo",
		runtimeinterface.SECRET_TYPE_CLUSTER:  "cluster",
	}

	client.getKeyFunc = map[runtimeinterface.SecretType]getSecretKey{
		runtimeinterface.SECRET_TYPE_GIT:      client.getGitSecretKey,
		runtimeinterface.SECRET_TYPE_ARTIFACT: client.getArtifactSecretKey,
	}

	return client, nil
}

func (s *Vault) Logout() error {
	err := s.client.Auth().Token().RevokeSelf("")
	if err != nil {
		logf.Log.Error(err, "revoke token failed")
		return err
	}
	return nil
}

func (s *Vault) GetAccessInfo(ctx context.Context, clusterName string) (string, error) {
	path := fmt.Sprintf(CLUSTER_PATH, clusterName)
	secret, err := s.client.KVv2(CLUSTER_NAMESPACE).Get(ctx, path)
	if err != nil {
		return "", err
	}
	kubeconfig, ok := secret.Data[CLUSTER_KUBECONFIG_KEY]
	if !ok {
		return "", fmt.Errorf("can not find kubeconfig in secret store. instance name %s", clusterName)
	}
	return kubeconfig.(string), nil
}

func newVaultClient(cfg configs.SecretRepo) (*vault.Client, error) {
	config := vault.DefaultConfig()
	config.Address = cfg.Vault.Addr

	if strings.HasPrefix(config.Address, "https://") {
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM([]byte(cfg.Vault.CABundle))
		config.HttpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: caCertPool,
				},
			},
		}
	}

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize Vault client: %w", err)
	}

	if cfg.Vault.Token != "" {
		client.SetToken(cfg.Vault.Token)
		return client, nil
	}

	var vaultOpts []kubernetesauth.LoginOption
	vaultOpts = append(vaultOpts, kubernetesauth.WithMountPath(cfg.Vault.MountPath))

	roleName, ok := cfg.OperatorName[_RUNTIME_OPERATOR_NAME]
	if !ok {
		return nil, fmt.Errorf("role name not found in nautes config")
	}
	k8sAuth, err := kubernetesauth.NewKubernetesAuth(
		roleName,
		vaultOpts...,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize Kubernetes auth method: %w", err)
	}

	authInfo, err := client.Auth().Login(context.Background(), k8sAuth)
	if err != nil {
		return nil, fmt.Errorf("unable to log in with Kubernetes auth: %w", err)
	}
	if authInfo == nil {
		return nil, fmt.Errorf("no auth info was returned after login")
	}
	return client, nil
}

func newVProxyClient(url, PKIPath string) (vaultproxy.SecretHTTPClient, vaultproxy.AuthHTTPClient, vaultproxy.AuthGrantHTTPClient, error) {
	ca, err := ioutil.ReadFile(filepath.Join(PKIPath, "ca.crt"))
	if err != nil {
		return nil, nil, nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(ca)

	cert, err := tls.LoadX509KeyPair(
		filepath.Join(PKIPath, "client.crt"),
		filepath.Join(PKIPath, "client.key"))
	if err != nil {
		return nil, nil, nil, err
	}

	tlsConfig := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{cert},
	}

	newTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	httpClient, err := kratos.NewClient(context.Background(),
		kratos.WithTransport(newTransport),
		kratos.WithEndpoint(url),
		kratos.WithTLSConfig(tlsConfig))
	if err != nil {
		return nil, nil, nil, err
	}

	return vaultproxy.NewSecretHTTPClient(httpClient),
		vaultproxy.NewAuthHTTPClient(httpClient),
		vaultproxy.NewAuthGrantHTTPClient(httpClient),
		nil
}
