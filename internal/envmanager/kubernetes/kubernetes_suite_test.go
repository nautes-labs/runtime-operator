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
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	externalsecretcrd "github.com/external-secrets/external-secrets/apis/externalsecrets/v1alpha1"
	nautescrd "github.com/nautes-labs/pkg/api/v1alpha1"
	convert "github.com/nautes-labs/pkg/pkg/kubeconvert"
	nautescfg "github.com/nautes-labs/pkg/pkg/nautesconfigs"
	secmock "github.com/nautes-labs/runtime-operator/internal/secret/mock"
	secprovider "github.com/nautes-labs/runtime-operator/internal/secret/provider"
	runtimecontext "github.com/nautes-labs/runtime-operator/pkg/context"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/kubectl/pkg/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	hncv1alpha2 "sigs.k8s.io/hierarchical-namespaces/api/v1alpha2"
)

func TestKubernetes(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Kubernetes Suite")
}

var cfg *rest.Config
var k8sClient client.Client
var testEnv *envtest.Environment
var ctx context.Context
var nautesCFG *nautescfg.Config
var mockK8SClient *mockClient

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	fmt.Printf("start test env: %s\n", time.Now())
	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("../../..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}

	err := errors.New("")
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	err = externalsecretcrd.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())
	err = hncv1alpha2.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())
	err = nautescrd.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())
	err = corev1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	//+kubebuilder:scaffold:scheme

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	fmt.Printf("init test env: %s\n", time.Now())

	initEnv()
	fmt.Printf("init env finish: %s\n", time.Now())
})

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})

func initEnv() {
	secprovider.SecretProviders = map[string]secprovider.NewClient{"vault": secmock.NewMock}
	kubeconfigCR := convert.ConvertRestConfigToApiConfig(*cfg)

	kubeconfig, err := clientcmd.Write(kubeconfigCR)
	Expect(err).Should(BeNil())

	err = os.Setenv("TEST_KUBECONFIG", string(kubeconfig))
	Expect(err).Should(BeNil())

	nautesCFG, err = nautescfg.NewConfig(`
secret:
  repoType: vault
`)
	Expect(err).Should(BeNil())
	ctx = context.Background()
	ctx = runtimecontext.NewNautesConfigContext(ctx, *nautesCFG)

	secClient, err := secprovider.GetSecretClient(ctx)
	Expect(err).Should(BeNil())
	ctx = runtimecontext.NewSecretClientContext(ctx, secClient)

	k8sClient.Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "nautes",
		},
	})

	mockK8SClient = &mockClient{}

}

func randNum() string {
	return fmt.Sprintf("%04d", rand.Intn(9999))
}

func isNotTerminatingAndBelongsToProduct(res client.Object, productName string) bool {
	if !res.GetDeletionTimestamp().IsZero() {
		return false
	}
	labels := res.GetLabels()
	name, ok := labels[nautescrd.LABEL_BELONG_TO_PRODUCT]
	if !ok || name != productName {
		return false
	}
	return true
}

type mockClient struct {
	ArtifactProvider *nautescrd.ArtifactRepoProvider
	ArtifactRepos    []nautescrd.ArtifactRepo
	CodeRepos        []nautescrd.CodeRepo
}

func (c *mockClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object) error {
	obj.(*nautescrd.ArtifactRepoProvider).ObjectMeta = c.ArtifactProvider.ObjectMeta
	obj.(*nautescrd.ArtifactRepoProvider).Spec = c.ArtifactProvider.Spec
	return nil
}

func (c *mockClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	switch obj := list.(type) {
	case *nautescrd.CodeRepoList:
		for _, coderepo := range c.CodeRepos {
			obj.Items = append(obj.Items, coderepo)
		}
		return nil
	case *nautescrd.ArtifactRepoList:
		list.(*nautescrd.ArtifactRepoList).Items = c.ArtifactRepos
		return nil
	}
	return fmt.Errorf("unknow list type")
}

func (c *mockClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	return nil
}

func (c *mockClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	return nil
}

func (c *mockClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	return nil
}

func (c *mockClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	return nil
}

func (c *mockClient) DeleteAllOf(ctx context.Context, obj client.Object, opts ...client.DeleteAllOfOption) error {
	return nil
}

func (c *mockClient) Status() client.StatusWriter {
	return nil
}

func (c *mockClient) Scheme() *runtime.Scheme {
	return nil
}

func (c *mockClient) RESTMapper() meta.RESTMapper {
	return nil
}
