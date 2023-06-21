# Runtime Operator

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![golang](https://img.shields.io/badge/golang-v1.20.5-brightgreen)](https://go.dev/doc/install)
[![version](https://img.shields.io/badge/version-v0.3.3-green)]()

Runtime Operator 项目提供了一组用于调谐 Project Pipeline Runtime 资源和 Deployment Runtime 资源事件的 Controller，调谐内容主要是根据两类运行时资源的声明信息，在目标集群上同步流水线执行或应用部署所需的基础环境。

## 功能简介

### 同步部署运行时

Controller 会根据 Deployment Runtime 资源引用的 Environment 资源找到运行时的目标集群，并在此集群上完成以下操作：

- 在管理命名空间中同步 Deployment Runtime 资源引用的 CodeRepo 资源。
- 根据 Deployment Runtime 资源关联的 Product 资源的名称同步产品命名空间，并在命名空间中同步 Role 为 namespace-admin、Group 为产品名称的 RoleBinding 资源。
- 根据 Deployment Runtime 资源的名称同步运行时命名空间，并在命名空间中同步运行时 SA。
- 在产品命名空间和运行时命名空间之间建立父子关系。
- 根据 Deployment Runtime 资源关联的 Product 资源的名称在 ArgoCD 中同步 AppProject。
- 根据 Deployment Runtime 资源的名称在 ArgoCD 中同步 Application，Application 的源为 Deployment Runtime 资源引用的 CodeRepo 资源、目标为运行时命名空间。
- 根据 Deployment Runtime 资源关联的 Product 资源的产品名称在 ArgoCD 中同步 Group，并为该 Group 授权上述 AppProject 的只读权限和 Application 的管理权限。

### 同步流水线运行时

- Controller 会根据 Project Pipeline Runtime 资源引用的 Environment 资源找到运行时的目标集群，并在此集群上完成以下操作：

  - 创建产品和流水线运行时的命名空间。
  - 根据运行时资源中定义的 Event Sources 创建事件监听器，监听器会接收 GitLab Webhook、Calender 等外部事件源产生的事件并将其转为内部事件。
  - 根据运行时资源中定义的 Pipeline Triggers 创建流水线触发器，触发器会根据事件监听器发出的内部事件触发指定的流水线。
  - 创建流水线模板同步程序，同步程序会将 default.project 项目指定路径下的流水线模板同步至集群，供产品中各个流水线使用。
  - 授权该运行时所属产品下的用户管理流水线实例的权限。

## 快速开始

### 准备

安装以下工具，并配置 GOBIN 环境变量：

- [go](https://golang.org/dl/)
- [kubectl](https://kubernetes.io/docs/tasks/tools/)

准备一个 kubernetes 实例，复制 kubeconfig 文件到 {$HOME}/.kube/config

### 构建

```shell
go mod tidy
go build -o manager main.go
```

### 运行
```shell
./manager
```

### 单元测试

安装 Vault

```shell
wget https://releases.hashicorp.com/vault/1.10.4/vault_1.10.4_linux_amd64.zip
unzip vault_1.10.4_linux_amd64.zip
sudo mv vault /usr/local/bin/
```

安装 Ginkgo

```shell
go install github.com/onsi/ginkgo/v2/ginkgo@v2.3.1
```

执行单元测试

```shell
make test
```
