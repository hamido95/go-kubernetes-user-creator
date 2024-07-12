# Kubernetes User Creator

This repository contains a Golang script to create Kubernetes users, generate RSA keys, create and approve CSRs, and configure kubeconfig with specified roles and bindings.

## Features

- Generates RSA keys and CSRs for a new Kubernetes user.
- Applies and approves Kubernetes CSR.
- Creates roles, cluster roles, role bindings, and cluster role bindings.
- Configures kubeconfig for the new user.

## Usage

To create a new Kubernetes user with specific roles and bindings:

```sh
go run main.go \
    -username <username> \
    -dir <directory> \
    -expiration <expiration_seconds> \
    -kubeconfig <kubeconfig_path> \
    -cluster <cluster_name> \
    -role-rules "namespace1:apiGroup1;apiGroup2:resource1;resource2:verb1;verb2:resourceName1;resourceName2,namespace2:apiGroup3:resource3:verb3" \
    -clusterrole-rules "apiGroup1:resource1:verb1:resourceName1,apiGroup2:resource2:verb2" \
    -role-bindings "namespace1:roleName1,namespace2:roleName2" \
    -clusterrole-bindings "clusterRoleName1,clusterRoleName2"
```

## Requirements
- Go 1.16+
- Kubernetes cluster
- kubectl installed and configured

## Installation

Clone the repository:
```
git clone https://github.com/yourusername/kubernetes-user-creator.git

cd kubernetes-user-creator
```

Build the project:
```
go build -o kubernetes-user-creator main.go
```

Run the project:
```
./kubernetes-user-creator \
    -username <username> \
    -dir <directory> \
    -expiration <expiration_seconds> \
    -kubeconfig <kubeconfig_path> \
    -cluster <cluster_name> \
    -role-rules "namespace:apiGroups:resources:verbs:resourceNames" \
    -clusterrole-rules "apiGroups:resources:verbs:resourceNames" \
    -role-bindings "namespace:roleName" \
    -clusterrole-bindings "clusterRoleName"
```

## License
This project is licensed under the MIT License. See the LICENSE file for details.