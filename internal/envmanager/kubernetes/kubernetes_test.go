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

package kubernetes_test

import (
	"fmt"
	"os"

	nautescrd "github.com/nautes-labs/pkg/api/v1alpha1"
	envmgr "github.com/nautes-labs/runtime-operator/internal/envmanager/kubernetes"
	interfaces "github.com/nautes-labs/runtime-operator/pkg/interface"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	hncv1alpha2 "sigs.k8s.io/hierarchical-namespaces/api/v1alpha2"
)

const (
	_HNC_CONFIG_NAME = "hierarchy"
)

var _ = Describe("EnvManager", func() {
	var err error
	var mgr envmgr.Syncer
	var productName string
	var groupName string
	var runtimeName string
	var artifactRepoName string
	var secretDBName string
	var secretKey string

	var accessInfo *interfaces.AccessInfo
	var baseRuntime *nautescrd.DeploymentRuntime
	var productNamespaceIsTerminating bool
	var artifactRepos []nautescrd.ArtifactRepo

	var task interfaces.RuntimeSyncTask
	BeforeEach(func() {
		productName = fmt.Sprintf("test-project-%s", randNum())
		groupName = fmt.Sprintf("group-%s", randNum())
		runtimeName = fmt.Sprintf("runtime-%s", randNum())
		artifactRepoName = fmt.Sprintf("artifact-repo-%s", randNum())
		secretDBName = "repo"

		accessInfo, err = mgr.GetAccessInfo(ctx, nautescrd.Cluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "aa",
				Namespace: "bb",
			},
		})
		Expect(err).Should(BeNil())

		baseRuntime = &nautescrd.DeploymentRuntime{
			ObjectMeta: metav1.ObjectMeta{
				Name:      runtimeName,
				Namespace: productName,
			},
			Spec: nautescrd.DeploymentRuntimeSpec{
				Product:        productName,
				ManifestSource: nautescrd.ManifestSource{},
				Destination:    "",
			},
		}

		task = interfaces.RuntimeSyncTask{
			AccessInfo: *accessInfo,
			Product: nautescrd.Product{
				ObjectMeta: metav1.ObjectMeta{
					Name:      productName,
					Namespace: nautesCFG.Nautes.Namespace,
				},
				Spec: nautescrd.ProductSpec{
					Name: groupName,
				},
			},
			NautesCfg:   *nautesCFG,
			Runtime:     baseRuntime,
			RuntimeType: interfaces.RUNTIME_TYPE_DEPLOYMENT,
		}

		artifactProvier := &nautescrd.ArtifactRepoProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "stander",
				Namespace: nautesCFG.Nautes.Namespace,
			},
			Spec: nautescrd.ArtifactRepoProviderSpec{
				URL:          "",
				APIServer:    "",
				ProviderType: "harbor",
			},
		}

		artifactRepos = []nautescrd.ArtifactRepo{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      artifactRepoName,
					Namespace: productName,
				},
				Spec: nautescrd.ArtifactRepoSpec{
					ArtifactRepoProvider: artifactProvier.Name,
					Product:              productName,
					Projects:             []string{},
					RepoName:             artifactRepoName,
					RepoType:             "",
					PackageType:          "",
				},
			},
		}

		mockK8SClient.ArtifactProvider = artifactProvier
		mockK8SClient.ArtifactRepos = artifactRepos
		productNamespaceIsTerminating = true

		secretKey = fmt.Sprintf("%s/%s/%s/default/readonly", artifactProvier.Name, artifactProvier.Spec.ProviderType, artifactRepos[0].Name)
		err = os.Setenv("TEST_SECRET_DB", secretDBName)
		Expect(err).Should(BeNil())
		err = os.Setenv("TEST_SECRET_KEY", secretKey)
		Expect(err).Should(BeNil())

		mgr = envmgr.Syncer{mockK8SClient}
	})

	AfterEach(func() {
		err = mgr.Remove(ctx, task)
		Expect(err).Should(BeNil())

		ns := &corev1.Namespace{}
		key := types.NamespacedName{
			Name: productName,
		}
		err = k8sClient.Get(ctx, key, ns)
		Expect(err).Should(BeNil())
		ok := isNotTerminatingAndBelongsToProduct(ns, productName)
		Expect(ok).ShouldNot(Equal(productNamespaceIsTerminating))

		key = types.NamespacedName{
			Name: runtimeName,
		}
		err = k8sClient.Get(ctx, key, ns)
		Expect(err).Should(BeNil())
		ok = isNotTerminatingAndBelongsToProduct(ns, productName)
		Expect(ok).Should(BeFalse())

		key = types.NamespacedName{
			Namespace: runtimeName,
			Name:      _HNC_CONFIG_NAME,
		}
		hnc := &hncv1alpha2.HierarchyConfiguration{}
		err = k8sClient.Get(ctx, key, hnc)
		Expect(client.IgnoreNotFound(err)).Should(BeNil())
	})

	It("init a new env", func() {
		_, err = mgr.Sync(ctx, task)
		Expect(err).Should(BeNil())
		ns := &corev1.Namespace{}
		key := types.NamespacedName{
			Name: productName,
		}
		err = k8sClient.Get(ctx, key, ns)
		Expect(err).Should(BeNil())
		ok := isNotTerminatingAndBelongsToProduct(ns, productName)
		Expect(ok).Should(BeTrue())

		key = types.NamespacedName{
			Name: runtimeName,
		}
		err = k8sClient.Get(ctx, key, ns)
		Expect(err).Should(BeNil())
		ok = isNotTerminatingAndBelongsToProduct(ns, productName)
		Expect(ok).Should(BeTrue())

		key = types.NamespacedName{
			Namespace: runtimeName,
			Name:      _HNC_CONFIG_NAME,
		}
		hnc := &hncv1alpha2.HierarchyConfiguration{}
		err = k8sClient.Get(ctx, key, hnc)
		Expect(err).Should(BeNil())
		ok = isNotTerminatingAndBelongsToProduct(hnc, productName)
		Expect(ok).Should(BeTrue())
	})

	It("update exited env", func() {
		_, err = mgr.Sync(ctx, task)
		Expect(err).Should(BeNil())

		_, err = mgr.Sync(ctx, task)
		Expect(err).Should(BeNil())
		ns := &corev1.Namespace{}
		key := types.NamespacedName{
			Name: productName,
		}
		err = k8sClient.Get(ctx, key, ns)
		Expect(err).Should(BeNil())
		ok := isNotTerminatingAndBelongsToProduct(ns, productName)
		Expect(ok).Should(BeTrue())

		key = types.NamespacedName{
			Name: runtimeName,
		}
		err = k8sClient.Get(ctx, key, ns)
		Expect(err).Should(BeNil())
		ok = isNotTerminatingAndBelongsToProduct(ns, productName)
		Expect(ok).Should(BeTrue())

		key = types.NamespacedName{
			Namespace: runtimeName,
			Name:      _HNC_CONFIG_NAME,
		}
		hnc := &hncv1alpha2.HierarchyConfiguration{}
		err = k8sClient.Get(ctx, key, hnc)
		Expect(err).Should(BeNil())
		ok = isNotTerminatingAndBelongsToProduct(hnc, productName)
		Expect(ok).Should(BeTrue())
	})

	It("if namespace parent is not product, change it back to product", func() {
		_, err = mgr.Sync(ctx, task)
		Expect(err).Should(BeNil())

		key := types.NamespacedName{
			Namespace: runtimeName,
			Name:      _HNC_CONFIG_NAME,
		}
		hnc := &hncv1alpha2.HierarchyConfiguration{}
		err = k8sClient.Get(ctx, key, hnc)
		Expect(err).Should(BeNil())

		hnc.Spec.Parent = fmt.Sprintf("other-product-%s", randNum())
		err = k8sClient.Update(ctx, hnc)
		Expect(err).Should(BeNil())

		_, err = mgr.Sync(ctx, task)
		Expect(err).Should(BeNil())

		err = k8sClient.Get(ctx, key, hnc)
		Expect(err).Should(BeNil())
		Expect(hnc.Spec.Parent).Should(Equal(productName))

	})

	It("do not delete product namespace if deployment has other runtime", func() {
		_, err = mgr.Sync(ctx, task)
		Expect(err).Should(BeNil())

		k8sClient.Create(ctx, &hncv1alpha2.HierarchyConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name:      _HNC_CONFIG_NAME,
				Namespace: productName,
			},
			Status: hncv1alpha2.HierarchyConfigurationStatus{
				Children: []string{randNum()},
			},
		})
		productNamespaceIsTerminating = false
		err = mgr.Remove(ctx, task)
		Expect(err).Should(BeNil())

		ns := &corev1.Namespace{}
		key := types.NamespacedName{
			Name: productName,
		}
		err = k8sClient.Get(ctx, key, ns)
		Expect(err).Should(BeNil())
		ok := isNotTerminatingAndBelongsToProduct(ns, productName)
		Expect(ok).Should(BeTrue())

		key = types.NamespacedName{
			Name: runtimeName,
		}
		err = k8sClient.Get(ctx, key, ns)
		Expect(err).Should(BeNil())
		ok = isNotTerminatingAndBelongsToProduct(ns, productName)
		Expect(ok).Should(BeFalse())

		key = types.NamespacedName{
			Namespace: runtimeName,
			Name:      _HNC_CONFIG_NAME,
		}
		hnc := &hncv1alpha2.HierarchyConfiguration{}
		err = k8sClient.Get(ctx, key, hnc)
		Expect(client.IgnoreNotFound(err)).Should(BeNil())
	})

	It("if namespace is not belongs to runtime, it should not be delete", func() {
		_, err = mgr.Sync(ctx, task)
		Expect(err).Should(BeNil())

		ns := &corev1.Namespace{}
		key := types.NamespacedName{
			Name: runtimeName,
		}
		err = k8sClient.Get(ctx, key, ns)
		Expect(err).Should(BeNil())
		ns.Labels = map[string]string{}
		err = k8sClient.Update(ctx, ns)
		Expect(err).Should(BeNil())

		err = mgr.Remove(ctx, task)
		Expect(err).Should(BeNil())

		ns = &corev1.Namespace{}
		key = types.NamespacedName{
			Name: runtimeName,
		}
		err = k8sClient.Get(ctx, key, ns)
		Expect(err).Should(BeNil())
		Expect(ns.DeletionTimestamp.IsZero()).Should(BeTrue())

		err = k8sClient.Delete(ctx, ns)
		Expect(err).Should(BeNil())
	})
})
