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
	"reflect"

	nautescrd "github.com/nautes-labs/pkg/api/v1alpha1"
	nautescfg "github.com/nautes-labs/pkg/pkg/nautesconfigs"
	runtimecontext "github.com/nautes-labs/runtime-operator/pkg/context"
	runtimeinterface "github.com/nautes-labs/runtime-operator/pkg/interface"

	"github.com/nautes-labs/runtime-operator/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	hncv1alpha2 "sigs.k8s.io/hierarchical-namespaces/api/v1alpha2"

	externalsecretcrd "github.com/external-secrets/external-secrets/apis/externalsecrets/v1alpha1"

	esmetav1 "github.com/external-secrets/external-secrets/apis/meta/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(rbacv1.AddToScheme(scheme))
	utilruntime.Must(nautescrd.AddToScheme(scheme))
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(hncv1alpha2.AddToScheme(scheme))
	utilruntime.Must(externalsecretcrd.AddToScheme(scheme))
}

const (
	_HNC_CONFIG_NAME               = "hierarchy"
	_ROLE_BINDING_NAME_PRODUCT     = "product-role-binding"
	_PROVIDER_VAULT_REPO_BASE_PATH = "repo"
)

var (
	// external secret format stander string + db name + repo ID
	externalSecretNameFormat = "nautes-external-secret-%s-%s"
	// secret format stander string + db name + repo ID
	secretNameFormat = "nautes-secret-%s-%s"
	// secret format stander string + db name
	secretStoreNameFormat = "natues-secret-store-%s"
	roleBindingTemplate   = rbacv1.RoleBinding{
		Subjects: []rbacv1.Subject{
			{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Group",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "cluster-admin",
		},
	}
)

type product struct {
	Name      string
	GroupName string
}

type cluster struct {
	Name             string
	ProductNamespace string
	Namespace        string
}

type destCluster struct {
	Product            product
	Cluster            cluster
	Runtime            runtimeinterface.Runtime
	cfg                nautescfg.Config
	resouceLable       map[string]string
	SecretStoreType    string
	secClient          runtimeinterface.SecretClient
	k8sClient          client.Client
	serviceAccountName string
}

func newDestCluster(ctx context.Context, task runtimeinterface.RuntimeSyncTask) (*destCluster, error) {
	if task.AccessInfo.Type != runtimeinterface.ACCESS_TYPE_K8S {
		return nil, fmt.Errorf("access type is not supported")
	}

	k8sClient, err := client.New(task.AccessInfo.Kubernetes, client.Options{Scheme: scheme})
	if err != nil {
		return nil, err
	}

	secClient, ok := runtimecontext.FromSecretClientConetxt(ctx)
	if !ok {
		return nil, fmt.Errorf("get secret client from context failed")
	}

	cluster := &destCluster{
		Product: product{
			Name:      task.Product.Name,
			GroupName: task.Product.Spec.Name,
		},
		Cluster: cluster{
			Name:             task.AccessInfo.Name,
			ProductNamespace: task.Product.Name,
			Namespace:        task.Runtime.GetName(),
		},
		Runtime:            task.Runtime,
		cfg:                task.NautesCfg,
		resouceLable:       task.GetLabel(),
		serviceAccountName: task.ServiceAccountName,
		SecretStoreType:    string(task.NautesCfg.Secret.RepoType),
		secClient:          secClient,
		k8sClient:          k8sClient,
	}

	return cluster, nil
}

func (c *destCluster) syncProductNamespace(ctx context.Context, codeRepo *nautescrd.CodeRepo) error {
	namespaceName := c.Product.Name
	if codeRepo == nil {
		return fmt.Errorf("product code repo can not be nil")
	}

	if err := c.syncNamespace(ctx, namespaceName); err != nil {
		return fmt.Errorf("sync namespace %s failed: %w", namespaceName, err)
	}

	codeRepo.Namespace = c.cfg.Nautes.Namespace
	if err := c.syncCodeRepo(ctx, *codeRepo); err != nil {
		return fmt.Errorf("sync code repo %s failed: %w", codeRepo.Name, err)
	}

	return nil
}

const (
	SecretNameSecretStoreCA = "ca"
	secretKeySecretStoreCA  = "ca.crt"
)

func (c *destCluster) syncRuntimeNamespace(ctx context.Context, codeRepo *nautescrd.CodeRepo) error {
	namespaceName := c.Runtime.GetName()
	if err := c.syncNamespace(ctx, namespaceName); err != nil {
		return fmt.Errorf("sync namespace %s failed: %w", namespaceName, err)
	}

	if err := c.SyncRole(ctx, namespaceName); err != nil {
		return fmt.Errorf("sync role %s failed: %w", namespaceName, err)
	}

	if err := c.syncCA(ctx, namespaceName); err != nil {
		return fmt.Errorf("sync secret store ca failed: %w", err)
	}

	return nil
}

func (c *destCluster) syncCA(ctx context.Context, namespaceName string) error {
	ca, err := c.secClient.GetCABundle(ctx)
	if err != nil {
		return fmt.Errorf("get secret store ca bundle failed: %w", err)
	}
	secretStoreCASecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      SecretNameSecretStoreCA,
			Namespace: namespaceName,
		},
	}

	if ca != "" {
		_, err := controllerutil.CreateOrUpdate(ctx, c.k8sClient, secretStoreCASecret, func() error {
			secretStoreCASecret.Data = map[string][]byte{
				secretKeySecretStoreCA: []byte(ca),
			}
			return nil
		})
		if err != nil {
			return err
		}
	} else {
		err := c.k8sClient.Delete(ctx, secretStoreCASecret)
		if client.IgnoreNotFound(err) != nil {
			return err
		}
	}

	return nil
}

func (c *destCluster) syncNamespace(ctx context.Context, name string) error {
	namespace := &corev1.Namespace{}
	key := types.NamespacedName{
		Name: name,
	}

	err := c.k8sClient.Get(ctx, key, namespace)
	if err != nil {
		if client.IgnoreNotFound(err) != nil {
			return err
		}

		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:   key.Name,
				Labels: c.resouceLable,
			},
		}
		return c.k8sClient.Create(ctx, namespace)
	}

	reason, ok := utils.IsLegal(namespace, c.Product.Name)
	if !ok {
		return fmt.Errorf(reason)
	}

	return nil
}

func (c *destCluster) syncCodeRepo(ctx context.Context, coderepo nautescrd.CodeRepo) error {
	newCodeRepo := &nautescrd.CodeRepo{
		ObjectMeta: metav1.ObjectMeta{
			Name:      coderepo.Name,
			Namespace: coderepo.Namespace,
		},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, c.k8sClient, newCodeRepo, func() error {
		newCodeRepo.Spec = coderepo.Spec
		return nil
	})
	return err
}

func (c *destCluster) syncRelationShip(ctx context.Context) error {
	labels := map[string]string{nautescrd.LABEL_BELONG_TO_PRODUCT: c.Product.Name}

	hncConfig := &hncv1alpha2.HierarchyConfiguration{}
	key := types.NamespacedName{
		Namespace: c.Runtime.GetName(),
		Name:      _HNC_CONFIG_NAME,
	}
	err := c.k8sClient.Get(ctx, key, hncConfig)
	if err != nil {
		if client.IgnoreNotFound(err) != nil {
			return err
		}

		hncConfig := &hncv1alpha2.HierarchyConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name:      key.Name,
				Namespace: key.Namespace,
				Labels:    labels,
			},
			Spec: hncv1alpha2.HierarchyConfigurationSpec{
				Parent: c.Product.Name,
			},
		}

		return c.k8sClient.Create(ctx, hncConfig)
	}

	reason, ok := utils.IsLegal(hncConfig, c.Product.Name)
	if !ok {
		return fmt.Errorf(reason)
	}

	if hncConfig.Spec.Parent == c.Product.Name {
		return nil
	}

	hncConfig.Spec.Parent = c.Product.Name
	return c.k8sClient.Update(ctx, hncConfig)
}

func (c *destCluster) syncProductAuthority(ctx context.Context) error {
	return c.syncAuthority(ctx, c.Product.Name, c.Product.GroupName)
}

func (c *destCluster) syncAuthority(ctx context.Context, namespace, groupName string) error {
	roleBinding := &rbacv1.RoleBinding{}
	key := types.NamespacedName{
		Namespace: namespace,
		Name:      _ROLE_BINDING_NAME_PRODUCT,
	}

	subjects := make([]rbacv1.Subject, len(roleBindingTemplate.Subjects))
	copy(subjects, roleBinding.Subjects)
	subjects[0].APIGroup = roleBindingTemplate.Subjects[0].APIGroup
	subjects[0].Kind = roleBindingTemplate.Subjects[0].Kind
	subjects[0].Name = groupName

	err := c.k8sClient.Get(ctx, key, roleBinding)
	if err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("get rolebinding failed: %w", err)
		}

		roleBinding := roleBindingTemplate.DeepCopy()
		roleBinding.Name = key.Name
		roleBinding.Namespace = key.Namespace
		roleBinding.Labels = c.resouceLable
		roleBinding.Subjects = subjects
		return c.k8sClient.Create(ctx, roleBinding)
	}

	reason, ok := utils.IsLegal(roleBinding, c.Product.Name)
	if !ok {
		return fmt.Errorf(reason)
	}

	needUpdate := false
	if reflect.DeepEqual(roleBinding.Subjects, subjects) {
		needUpdate = true
		roleBinding.Subjects = subjects
	}

	if reflect.DeepEqual(roleBinding.RoleRef, roleBindingTemplate.RoleRef) {
		needUpdate = true
		roleBinding.RoleRef = roleBindingTemplate.RoleRef
	}

	if needUpdate == false {
		return nil
	}

	return c.k8sClient.Update(ctx, roleBinding)
}

func (c *destCluster) deleteNamespace(ctx context.Context, namespaceName string) error {
	namespace := &corev1.Namespace{}
	key := types.NamespacedName{
		Name: namespaceName,
	}

	err := c.k8sClient.Get(ctx, key, namespace)
	if err != nil {
		if client.IgnoreNotFound(err) != nil {
			return err
		}

		return nil
	}

	if !utils.IsBelongsToProduct(namespace, c.Product.Name) {
		return nil
	}

	if err := c.DeleteRole(ctx, key.Name); err != nil {
		return fmt.Errorf("delete role failed: %w", err)
	}

	return c.k8sClient.Delete(ctx, namespace)
}

// checkProductNamespaceIsUsing will not delete product namespace if it is using
// it product namespace can not be delete, the bool return will be false
func (c *destCluster) checkProductNamespaceIsUsing(ctx context.Context) (bool, error) {
	namespace := &corev1.Namespace{}
	key := types.NamespacedName{
		Name: c.Product.Name,
	}

	err := c.k8sClient.Get(ctx, key, namespace)
	if err != nil {
		if client.IgnoreNotFound(err) != nil {
			return false, err
		}
		return true, nil
	}

	label, ok := namespace.Labels[nautescrd.LABEL_BELONG_TO_PRODUCT]
	if !ok || label != c.Product.Name {
		return false, nil
	}

	hncConfig := &hncv1alpha2.HierarchyConfiguration{}
	hncKey := types.NamespacedName{
		Namespace: c.Product.Name,
		Name:      _HNC_CONFIG_NAME,
	}

	err = c.k8sClient.Get(ctx, hncKey, hncConfig)
	if err != nil {
		if client.IgnoreNotFound(err) != nil {
			return false, err
		}
		return true, nil
	}

	children := hncConfig.Status.Children
	for i, child := range children {
		if child == c.Runtime.GetName() {
			children = append(children[:i], children[i+1:]...)
		}
	}

	log.FromContext(ctx).V(1).Info(fmt.Sprintf("product %s has chilren %s", c.Product, children))
	return len(children) == 0, nil
}

func (c *destCluster) deleteProductNamespace(ctx context.Context, codeRepo *nautescrd.CodeRepo) error {
	codeRepo.Namespace = c.cfg.Nautes.Namespace
	err := c.k8sClient.Delete(ctx, codeRepo)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("get product coderepo failed: %w", err)
	}
	return c.deleteNamespace(ctx, c.Product.Name)
}

func (c *destCluster) SyncRole(ctx context.Context, namespaceName string) error {
	sa := &corev1.ServiceAccount{}
	key := types.NamespacedName{
		Namespace: namespaceName,
		Name:      c.serviceAccountName,
	}
	if err := c.k8sClient.Get(ctx, key, sa); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return err
		}

		sa := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      key.Name,
				Namespace: key.Namespace,
				Labels:    c.resouceLable,
			},
		}
		if err := c.k8sClient.Create(ctx, sa); err != nil {
			return fmt.Errorf("create service account failed: %w", err)
		}
	} else {
		reason, ok := utils.IsLegal(sa, c.Product.Name)
		if !ok {
			return fmt.Errorf("service account %s is not useable, %s", key.Name, reason)
		}
	}

	role := runtimeinterface.Role{
		Name:   key.Namespace,
		Users:  []string{c.serviceAccountName},
		Groups: []string{c.Cluster.Namespace},
	}
	clusterRole, err := c.secClient.GetRole(ctx, c.Cluster.Name, role)
	if err != nil {
		return err
	}
	if clusterRole != nil {
		return nil
	}
	return c.secClient.CreateRole(ctx, c.Cluster.Name, role)
}

func (c *destCluster) DeleteRole(ctx context.Context, namespaceName string) error {
	key := types.NamespacedName{
		Namespace: namespaceName,
		Name:      c.serviceAccountName,
	}

	if err := c.deleteResource(ctx, key, &corev1.ServiceAccount{}); err != nil {
		return fmt.Errorf("delete service account failed: %w", err)
	}
	role := runtimeinterface.Role{
		Name:   key.Namespace,
		Users:  []string{key.Name},
		Groups: []string{c.Cluster.Namespace},
	}

	return c.secClient.DeleteRole(ctx, c.Cluster.Name, role)
}

func (c destCluster) deleteResource(ctx context.Context, key types.NamespacedName, resource client.Object) error {
	if err := c.k8sClient.Get(ctx, key, resource); err != nil {
		return client.IgnoreNotFound(err)
	}

	ok := utils.IsBelongsToProduct(resource, c.Product.Name)
	if !ok {
		return fmt.Errorf("resource %s is not belongs to product %s", key.Name, c.Product.Name)
	}

	return c.k8sClient.Delete(ctx, resource)
}

func (c destCluster) SyncRepo(ctx context.Context, repos []runtimeinterface.SecretInfo) error {
	for _, repo := range repos {
		if err := c.syncSecretStore(ctx, repo); err != nil {
			return fmt.Errorf("sync secret store failed: %w", err)
		}

		if err := c.syncExternalSecret(ctx, repo); err != nil {
			return fmt.Errorf("sync external secret failed: %w", err)
		}
	}

	if err := c.cleanNoUseExternalSecret(ctx, repos); err != nil {
		return fmt.Errorf("clean no use external secret failed: %w", err)
	}

	return nil
}

type externalSecretOptions func(externalsecretcrd.ExternalSecretSpec)

func (c destCluster) syncExternalSecret(ctx context.Context, repo runtimeinterface.SecretInfo, opts ...externalSecretOptions) error {
	secretKey, err := c.secClient.GetSecretKey(ctx, repo)
	if err != nil {
		return fmt.Errorf("get repo key failed: %w", err)
	}

	dbName, err := c.secClient.GetSecretDatabaseName(ctx, repo)
	if err != nil {
		return fmt.Errorf("get repo dbname failed: %w", err)
	}

	secretID, err := getID(repo)
	if err != nil {
		return fmt.Errorf("get secret id failed: %w", err)
	}

	externalSecretName := fmt.Sprintf(externalSecretNameFormat, dbName, secretID)
	secretStoreName := fmt.Sprintf(secretStoreNameFormat, dbName)
	secretName := fmt.Sprintf(secretNameFormat, dbName, secretID)

	esSpec := externalsecretcrd.ExternalSecretSpec{
		SecretStoreRef: externalsecretcrd.SecretStoreRef{
			Name: secretStoreName,
			Kind: "SecretStore",
		},
		Target: externalsecretcrd.ExternalSecretTarget{
			Name:           secretName,
			CreationPolicy: "Owner",
		},
		Data: []externalsecretcrd.ExternalSecretData{
			{
				SecretKey: "token",
				RemoteRef: externalsecretcrd.ExternalSecretDataRemoteRef{
					Key:                secretKey,
					ConversionStrategy: "Default",
					Property:           "token",
				},
			},
		},
	}

	for _, fn := range opts {
		fn(esSpec)
	}

	es := &externalsecretcrd.ExternalSecret{}
	key := types.NamespacedName{
		Namespace: c.Cluster.Namespace,
		Name:      externalSecretName,
	}
	if err := c.k8sClient.Get(ctx, key, es); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return err
		}

		es := &externalsecretcrd.ExternalSecret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      key.Name,
				Namespace: key.Namespace,
				Labels:    c.resouceLable,
			},
			Spec: esSpec,
		}

		return c.k8sClient.Create(ctx, es)
	}

	reason, ok := utils.IsLegal(es, c.Product.Name)
	if !ok {
		return fmt.Errorf("external secret %s is not useable, %s", key.Name, reason)
	}

	if reflect.DeepEqual(es.Spec, esSpec) {
		return nil
	}
	es.Spec = esSpec

	return c.k8sClient.Update(ctx, es)
}

func (c destCluster) cleanNoUseExternalSecret(ctx context.Context, repos []runtimeinterface.SecretInfo) error {
	esList := &externalsecretcrd.ExternalSecretList{}
	listOpts := []client.ListOption{
		client.InNamespace(c.Cluster.Namespace),
		client.MatchingLabels(c.resouceLable),
	}

	if err := c.k8sClient.List(ctx, esList, listOpts...); err != nil {
		return err
	}

	noUseExternalSecrets := make([]externalsecretcrd.ExternalSecret, 0)
	if len(repos) != 0 {
		dbName, err := c.secClient.GetSecretDatabaseName(ctx, repos[0])
		if err != nil {
			return fmt.Errorf("get repo dbname failed: %w", err)
		}

		esNames := make([]string, 0)
		for _, repo := range repos {
			secretID, err := getID(repo)
			if err != nil {
				return fmt.Errorf("get secret id failed: %w", err)
			}
			esNames = append(esNames, fmt.Sprintf(externalSecretNameFormat, dbName, secretID))
		}

		noUseExternalSecrets = findNoUseExternalSecret(esNames, *esList)
	} else {
		noUseExternalSecrets = esList.Items
	}

	for _, es := range noUseExternalSecrets {
		err := c.k8sClient.Delete(ctx, &es)
		if err != nil {
			return err
		}
	}
	return nil
}

func findNoUseExternalSecret(esNames []string, externalSecretList externalsecretcrd.ExternalSecretList) []externalsecretcrd.ExternalSecret {
	noUseList := make([]externalsecretcrd.ExternalSecret, 0)
	for _, es := range externalSecretList.Items {
		deleteable := true
		for _, name := range esNames {
			if es.Name == name {
				deleteable = false
				break
			}
		}
		if deleteable {
			noUseList = append(noUseList, es)
		}
	}

	return noUseList
}

func (c destCluster) syncSecretStore(ctx context.Context, repo runtimeinterface.SecretInfo) error {
	dbName, err := c.secClient.GetSecretDatabaseName(ctx, repo)
	if err != nil {
		return fmt.Errorf("get repo dbname failed: %w", err)
	}

	provider := &externalsecretcrd.SecretStoreProvider{}
	switch c.SecretStoreType {
	case "vault":
		provider.Vault = c.getVaultSecretStore(dbName)
	default:
		return fmt.Errorf("secret type %s is not supported", c.cfg.Secret.RepoType)
	}

	secretstore := &externalsecretcrd.SecretStore{}
	key := types.NamespacedName{
		Namespace: c.Cluster.Namespace,
		Name:      fmt.Sprintf(secretStoreNameFormat, dbName),
	}
	if err := c.k8sClient.Get(ctx, key, secretstore); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return err
		}

		secretstore := &externalsecretcrd.SecretStore{
			ObjectMeta: metav1.ObjectMeta{
				Name:      key.Name,
				Namespace: key.Namespace,
				Labels:    c.resouceLable,
			},
			Spec: externalsecretcrd.SecretStoreSpec{
				Provider: provider,
			},
		}
		return c.k8sClient.Create(ctx, secretstore)
	}

	if reason, ok := utils.IsLegal(secretstore, c.Product.Name); !ok {
		return fmt.Errorf("secret store %s in %s is not usable: %s", key.Name, key.Namespace, reason)
	}

	if reflect.DeepEqual(secretstore.Spec.Provider, provider) {
		return nil
	}

	secretstore.Spec.Provider = provider
	return c.k8sClient.Update(ctx, secretstore)
}

func (c destCluster) getVaultSecretStore(dbName string) *externalsecretcrd.VaultProvider {
	provider := &externalsecretcrd.VaultProvider{
		Auth: externalsecretcrd.VaultAuth{
			Kubernetes: &externalsecretcrd.VaultKubernetesAuth{
				Path: c.Cluster.Name,
				ServiceAccountRef: &esmetav1.ServiceAccountSelector{
					Name: c.serviceAccountName,
				},
				Role: c.Runtime.GetName(),
			},
		},
		Server:  c.cfg.Secret.Vault.Addr,
		Path:    &dbName,
		Version: "v2",
	}
	return provider
}

func getID(repo runtimeinterface.SecretInfo) (string, error) {
	switch repo.Type {
	case runtimeinterface.SECRET_TYPE_GIT:
		if repo.CodeRepo == nil {
			return "", fmt.Errorf("code repo is nil")
		}
		return repo.CodeRepo.ID, nil
	case runtimeinterface.SECRET_TYPE_ARTIFACT:
		if repo.AritifaceRepo == nil {
			return "", fmt.Errorf("artifact repo is nil")
		}
		return repo.AritifaceRepo.ID, nil
	default:
		return "", fmt.Errorf("unknow secret type")
	}
}
