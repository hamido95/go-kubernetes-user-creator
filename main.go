package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

var (
	username            string
	dirName             string
	userExpirationSec   int64
	kubeConfigPath      string
	clusterName         string
	roleRules           string
	clusterRoleRules    string
	roleBindings        string
	clusterRoleBindings string
)

func init() {
	flag.StringVar(&username, "username", "supmu", "The username for the new user")
	flag.StringVar(&dirName, "dir", "/home/user/devtest/kubeuser/psp/supmu", "The directory to store keys and certs")
	flag.Int64Var(&userExpirationSec, "expiration", 315569520, "User expiration in seconds")
	flag.StringVar(&kubeConfigPath, "kubeconfig", "/home/user/.kube/psp-config", "Path to the kubeconfig file")
	flag.StringVar(&clusterName, "cluster", "kubernetes", "Kubernetes cluster name")
	flag.StringVar(&roleRules, "role-rules", "", "Comma-separated list of role rules in the format 'namespace:apiGroups:resources:verbs:resourceNames'")
	flag.StringVar(&clusterRoleRules, "clusterrole-rules", "", "Comma-separated list of cluster role rules in the format 'apiGroups:resources:verbs:resourceNames'")
	flag.StringVar(&roleBindings, "role-bindings", "", "Comma-separated list of role bindings in the format 'namespace:roleName'")
	flag.StringVar(&clusterRoleBindings, "clusterrole-bindings", "", "Comma-separated list of cluster role bindings in the format 'clusterRoleName'")
	flag.Parse()
}

func parseRules(rulesStr string) []v1.PolicyRule {
	var rules []v1.PolicyRule
	for _, ruleStr := range strings.Split(rulesStr, ",") {
		parts := strings.Split(ruleStr, ":")
		if len(parts) < 4 {
			fmt.Println("Invalid rule format")
			continue
		}

		rule := v1.PolicyRule{
			APIGroups: strings.Split(parts[1], ";"),
			Resources: strings.Split(parts[2], ";"),
			Verbs:     strings.Split(parts[3], ";"),
		}
		if len(parts) == 5 {
			rule.ResourceNames = strings.Split(parts[4], ";")
		}

		rules = append(rules, rule)
	}
	return rules
}

func parseBindings(bindingsStr string) []v1.Subject {
	var subjects []v1.Subject
	for _, bindingStr := range strings.Split(bindingsStr, ",") {
		parts := strings.Split(bindingStr, ":")
		if len(parts) < 2 {
			fmt.Println("Invalid binding format")
			continue
		}

		subject := v1.Subject{
			Kind:      "User",
			Name:      username,
			Namespace: parts[0],
		}
		subjects = append(subjects, subject)
	}
	return subjects
}

func createRole(clientset *kubernetes.Clientset, namespace string, rules []v1.PolicyRule) error {
	role := &v1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      username + "-role",
			Namespace: namespace,
		},
		Rules: rules,
	}

	_, err := clientset.RbacV1().Roles(namespace).Create(context.Background(), role, metav1.CreateOptions{})
	return err
}

func createClusterRole(clientset *kubernetes.Clientset, rules []v1.PolicyRule) error {
	clusterRole := &v1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: username + "-clusterrole",
		},
		Rules: rules,
	}

	_, err := clientset.RbacV1().ClusterRoles().Create(context.Background(), clusterRole, metav1.CreateOptions{})
	return err
}

func createRoleBinding(clientset *kubernetes.Clientset, namespace, roleName string) error {
	roleBinding := &v1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      username + "-rolebinding",
			Namespace: namespace,
		},
		Subjects: []v1.Subject{
			{
				Kind:      "User",
				Name:      username,
				Namespace: namespace,
			},
		},
		RoleRef: v1.RoleRef{
			Kind:     "Role",
			Name:     roleName,
			APIGroup: "rbac.authorization.k8s.io",
		},
	}

	_, err := clientset.RbacV1().RoleBindings(namespace).Create(context.Background(), roleBinding, metav1.CreateOptions{})
	return err
}

func createClusterRoleBinding(clientset *kubernetes.Clientset, clusterRoleName string) error {
	clusterRoleBinding := &v1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: username + "-clusterrolebinding",
		},
		Subjects: []v1.Subject{
			{
				Kind:     "User",
				Name:     username,
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
		RoleRef: v1.RoleRef{
			Kind:     "ClusterRole",
			Name:     clusterRoleName,
			APIGroup: "rbac.authorization.k8s.io",
		},
	}

	_, err := clientset.RbacV1().ClusterRoleBindings().Create(context.Background(), clusterRoleBinding, metav1.CreateOptions{})
	return err
}

func createRSAKey() (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	keyFile, err := os.Create(fmt.Sprintf("%s/%s.key", dirName, username))
	if err != nil {
		return nil, err
	}
	defer keyFile.Close()

	err = pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err != nil {
		return nil, err
	}

	return key, nil
}

func createCSR(key *rsa.PrivateKey) ([]byte, error) {
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: username,
		},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, key)
	if err != nil {
		return nil, err
	}

	csrFile, err := os.Create(fmt.Sprintf("%s/%s.csr", dirName, username))
	if err != nil {
		return nil, err
	}
	defer csrFile.Close()

	err = pem.Encode(csrFile, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	if err != nil {
		return nil, err
	}

	return csrBytes, nil
}

func main() {
	os.MkdirAll(dirName, os.ModePerm)

	key, err := createRSAKey()
	if err != nil {
		fmt.Printf("Error generating RSA key: %v\n", err)
		return
	}
	fmt.Println("Successfully generated RSA key...")

	csrBytes, err := createCSR(key)
	if err != nil {
		fmt.Printf("Error generating CSR: %v\n", err)
		return
	}
	fmt.Println("Successfully generated CSR...")

	cfg, err := config.GetConfig()
	if err != nil {
		fmt.Printf("Error getting kubeconfig: %v\n", err)
		return
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		fmt.Printf("Error creating Kubernetes client: %v\n", err)
		return
	}

	csrName := username
	encodedCSR := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	csr := &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: csrName,
		},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request:    encodedCSR,
			Usages:     []certificatesv1.KeyUsage{certificatesv1.UsageClientAuth},
			Expiry:     &metav1.Duration{Duration: userExpirationSec * time.Second},
			SignerName: "kubernetes.io/kube-apiserver-client",
		},
	}

	_, err = clientset.CertificatesV1().CertificateSigningRequests().Create(context.Background(), csr, metav1.CreateOptions{})
	if err != nil {
		fmt.Printf("Error creating Kubernetes CSR: %v\n", err)
		return
	}
	fmt.Println("Successfully applied Kubernetes CSR...")

	// Approve the CSR
	csr, err = clientset.CertificatesV1().CertificateSigningRequests().Get(context.Background(), csrName, metav1.GetOptions{})
	if err != nil {
		fmt.Printf("Error getting Kubernetes CSR: %v\n", err)
		return
	}

	csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
		Type:    certificatesv1.CertificateApproved,
		Status:  corev1.ConditionTrue,
		Reason:  "KubectlCreateUser",
		Message: "Approved by kubectl-create-user plugin",
	})

	_, err = clientset.CertificatesV1().CertificateSigningRequests().UpdateApproval(context.Background(), csrName, csr, metav1.UpdateOptions{})
	if err != nil {
		fmt.Printf("Error approving Kubernetes CSR: %v\n", err)
		return
	}
	fmt.Println("Successfully approved Kubernetes CSR...")

	// Fetch the signed certificate
	csr, err = clientset.CertificatesV1().CertificateSigningRequests().Get(context.Background(), csrName, metav1.GetOptions{})
	if err != nil {
		fmt.Printf("Error getting Kubernetes CSR: %v\n", err)
		return
	}

	crtBytes := csr.Status.Certificate
	crtFile, err := os.Create(fmt.Sprintf("%s/%s.crt", dirName, username))
	if err != nil {
		fmt.Printf("Error creating certificate file: %v\n", err)
		return
	}
	defer crtFile.Close()

	_, err = crtFile.Write(crtBytes)
	if err != nil {
		fmt.Printf("Error writing certificate file: %v\n", err)
		return
	}
	fmt.Println("Successfully created certificate file...")

	// Configure kubeconfig for the user
	kubeconfig, err := os.ReadFile(kubeConfigPath)
	if err != nil {
		fmt.Printf("Error reading kubeconfig: %v\n", err)
		return
	}

	kubeconfigPath := fmt.Sprintf("%s/%s-config", dirName, username)
	err = ioutil.WriteFile(kubeconfigPath, kubeconfig, 0644)
	if err != nil {
		fmt.Printf("Error writing user kubeconfig: %v\n", err)
		return
	}

	// Update kubeconfig with user credentials
	cmd := exec.Command("kubectl", "--kubeconfig", kubeconfigPath, "config", "set-credentials", username,
		"--client-key", fmt.Sprintf("%s/%s.key", dirName, username),
		"--client-certificate", fmt.Sprintf("%s/%s.crt", dirName, username),
		"--embed-certs=true")
	if err := cmd.Run(); err != nil {
		fmt.Printf("Error setting credentials in kubeconfig: %v\n", err)
		return
	}

	// Set context for the user
	cmd = exec.Command("kubectl", "--kubeconfig", kubeconfigPath, "config", "set-context", username,
		"--cluster", clusterName,
		"--user", username)
	if err := cmd.Run(); err != nil {
		fmt.Printf("Error setting context in kubeconfig: %v\n", err)
		return
	}

	cmd = exec.Command("kubectl", "--kubeconfig", kubeconfigPath, "config", "use-context", username)
	if err := cmd.Run(); err != nil {
		fmt.Printf("Error using context in kubeconfig: %v\n", err)
		return
	}

	fmt.Println("Congratulations... the user", username, "created successfully...")

	// Create Role, ClusterRole, RoleBinding, and ClusterRoleBinding if specified
	if roleRules != "" {
		rules := parseRules(roleRules)
		for _, rule := range rules {
			if err := createRole(clientset, rule.Namespace, rule.Rules); err != nil {
				fmt.Printf("Error creating Role: %v\n", err)
				return
			}
		}
		fmt.Println("Successfully created Roles...")
	}

	if clusterRoleRules != "" {
		rules := parseRules(clusterRoleRules)
		for _, rule := range rules {
			if err := createClusterRole(clientset, rule.Rules); err != nil {
				fmt.Printf("Error creating ClusterRole: %v\n", err)
				return
			}
		}
		fmt.Println("Successfully created ClusterRoles...")
	}

	if roleBindings != "" {
		bindings := parseBindings(roleBindings)
		for _, binding := range bindings {
			if err := createRoleBinding(clientset, binding.Namespace, binding.RoleName); err != nil {
				fmt.Printf("Error creating RoleBinding: %v\n", err)
				return
			}
		}
		fmt.Println("Successfully created RoleBindings...")
	}

	if clusterRoleBindings != "" {
		bindings := parseBindings(clusterRoleBindings)
		for _, binding := range bindings {
			if err := createClusterRoleBinding(clientset, binding.RoleName); err != nil {
				fmt.Printf("Error creating ClusterRoleBinding: %v\n", err)
				return
			}
		}
		fmt.Println("Successfully created ClusterRoleBindings...")
	}
}
