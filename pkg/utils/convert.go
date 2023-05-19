package utils

import (
	"context"
	"fmt"

	nautescrd "github.com/nautes-labs/pkg/api/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func GetCodeRepoProviderAndCodeRepoWithURL(ctx context.Context, k8sClient client.Client, repoKey types.NamespacedName, nautesNamespace string) (*nautescrd.CodeRepoProvider, *nautescrd.CodeRepo, error) {
	codeRepo := &nautescrd.CodeRepo{}
	if err := k8sClient.Get(ctx, repoKey, codeRepo); err != nil {
		return nil, nil, fmt.Errorf("get code repo faile: %w", err)
	}

	provider := &nautescrd.CodeRepoProvider{}
	providerKey := types.NamespacedName{
		Namespace: nautesNamespace,
		Name:      codeRepo.Spec.CodeRepoProvider,
	}
	if err := k8sClient.Get(ctx, providerKey, provider); err != nil {
		return nil, nil, fmt.Errorf("get provider failed: %w", err)
	}

	if codeRepo.Spec.URL != "" {
		return provider, codeRepo, nil
	}

	if codeRepo.Spec.RepoName == "" {
		return nil, nil, fmt.Errorf("repo name is empty")
	}

	product := &nautescrd.Product{}
	productKey := types.NamespacedName{
		Namespace: nautesNamespace,
		Name:      codeRepo.Spec.Product,
	}
	if err := k8sClient.Get(ctx, productKey, product); err != nil {
		return nil, nil, fmt.Errorf("get product failed: %w", err)
	}

	codeRepo.Spec.URL = fmt.Sprintf("%s/%s/%s", provider.Spec.SSHAddress, product.Spec.Name, codeRepo.Spec.RepoName)

	return provider, codeRepo, nil
}
