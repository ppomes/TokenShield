package controller

import (
    "context"
    "fmt"
    
    appsv1 "k8s.io/api/apps/v1"
    corev1 "k8s.io/api/core/v1"
    networkingv1 "k8s.io/api/networking/v1"
    "k8s.io/apimachinery/pkg/runtime"
    ctrl "sigs.k8s.io/controller-runtime"
    "sigs.k8s.io/controller-runtime/pkg/client"
    "sigs.k8s.io/controller-runtime/pkg/log"
    
    tokenizationv1alpha1 "github.com/tokenshield/operator/api/v1alpha1"
)

// TokenShieldReconciler reconciles a TokenShield object
type TokenShieldReconciler struct {
    client.Client
    Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=tokenization.io,resources=tokenshields,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=tokenization.io,resources=tokenshields/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;create;update;patch;delete

func (r *TokenShieldReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    log := log.FromContext(ctx)
    
    // Fetch the TokenShield instance
    tokenshield := &tokenizationv1alpha1.TokenShield{}
    if err := r.Get(ctx, req.NamespacedName, tokenshield); err != nil {
        return ctrl.Result{}, client.IgnoreNotFound(err)
    }
    
    // Update status to Creating
    tokenshield.Status.Phase = "Creating"
    if err := r.Status().Update(ctx, tokenshield); err != nil {
        return ctrl.Result{}, err
    }
    
    // Deploy components in order
    components := []func(context.Context, *tokenizationv1alpha1.TokenShield) error{
        r.reconcileDatabase,
        r.reconcileTokenizer,
        r.reconcileInboundProxy,
        r.reconcileOutboundProxy,
        r.reconcileDashboard,
        r.reconcileMonitoring,
    }
    
    for _, reconcileFunc := range components {
        if err := reconcileFunc(ctx, tokenshield); err != nil {
            log.Error(err, "Failed to reconcile component")
            tokenshield.Status.Phase = "Failed"
            tokenshield.Status.Message = err.Error()
            r.Status().Update(ctx, tokenshield)
            return ctrl.Result{}, err
        }
    }
    
    // Update status to Running
    tokenshield.Status.Phase = "Running"
    tokenshield.Status.Ready = true
    tokenshield.Status.Message = "All components are running"
    
    // Set endpoints
    tokenshield.Status.Endpoints = tokenizationv1alpha1.Endpoints{
        Tokenizer: fmt.Sprintf("http://tokenshield-tokenizer.%s.svc.cluster.local:8080", req.Namespace),
        API:       fmt.Sprintf("http://tokenshield-tokenizer.%s.svc.cluster.local:8090", req.Namespace),
        Dashboard: fmt.Sprintf("http://tokenshield-dashboard.%s.svc.cluster.local:80", req.Namespace),
    }
    
    if tokenshield.Spec.Dashboard.Ingress.Enabled {
        tokenshield.Status.Endpoints.Dashboard = fmt.Sprintf("https://%s", tokenshield.Spec.Dashboard.Ingress.Host)
    }
    
    if err := r.Status().Update(ctx, tokenshield); err != nil {
        return ctrl.Result{}, err
    }
    
    return ctrl.Result{RequeueAfter: time.Minute * 5}, nil
}

func (r *TokenShieldReconciler) reconcileDatabase(ctx context.Context, ts *tokenizationv1alpha1.TokenShield) error {
    log := log.FromContext(ctx)
    
    switch ts.Spec.Database.Type {
    case "mysql":
        return r.deployMySQL(ctx, ts)
    case "postgresql":
        return r.deployPostgreSQL(ctx, ts)
    default:
        return fmt.Errorf("unsupported database type: %s", ts.Spec.Database.Type)
    }
}

func (r *TokenShieldReconciler) deployMySQL(ctx context.Context, ts *tokenizationv1alpha1.TokenShield) error {
    // Create PVC for MySQL
    pvc := &corev1.PersistentVolumeClaim{
        ObjectMeta: metav1.ObjectMeta{
            Name:      "tokenshield-mysql-pvc",
            Namespace: ts.Namespace,
        },
        Spec: corev1.PersistentVolumeClaimSpec{
            AccessModes: []corev1.PersistentVolumeAccessMode{
                corev1.ReadWriteOnce,
            },
            Resources: corev1.ResourceRequirements{
                Requests: corev1.ResourceList{
                    corev1.ResourceStorage: resource.MustParse(ts.Spec.Database.Size),
                },
            },
        },
    }
    
    // Set TokenShield as owner
    ctrl.SetControllerReference(ts, pvc, r.Scheme)
    
    // Create or update PVC
    if err := r.Create(ctx, pvc); err != nil && !errors.IsAlreadyExists(err) {
        return err
    }
    
    // Create MySQL StatefulSet
    replicas := int32(1)
    if ts.Spec.HighAvailability.Enabled && ts.Spec.HighAvailability.Database.Replication {
        replicas = 3
    }
    
    statefulSet := &appsv1.StatefulSet{
        ObjectMeta: metav1.ObjectMeta{
            Name:      "tokenshield-mysql",
            Namespace: ts.Namespace,
        },
        Spec: appsv1.StatefulSetSpec{
            Replicas: &replicas,
            Selector: &metav1.LabelSelector{
                MatchLabels: map[string]string{
                    "app":       "tokenshield",
                    "component": "database",
                },
            },
            Template: corev1.PodTemplateSpec{
                ObjectMeta: metav1.ObjectMeta{
                    Labels: map[string]string{
                        "app":       "tokenshield",
                        "component": "database",
                    },
                },
                Spec: corev1.PodSpec{
                    Containers: []corev1.Container{
                        {
                            Name:  "mysql",
                            Image: "mysql:8.0",
                            Env: []corev1.EnvVar{
                                {
                                    Name: "MYSQL_ROOT_PASSWORD",
                                    ValueFrom: &corev1.EnvVarSource{
                                        SecretKeyRef: &corev1.SecretKeySelector{
                                            LocalObjectReference: corev1.LocalObjectReference{
                                                Name: ts.Spec.Database.ConnectionSecret,
                                            },
                                            Key: "password",
                                        },
                                    },
                                },
                                {
                                    Name: "MYSQL_DATABASE",
                                    ValueFrom: &corev1.EnvVarSource{
                                        SecretKeyRef: &corev1.SecretKeySelector{
                                            LocalObjectReference: corev1.LocalObjectReference{
                                                Name: ts.Spec.Database.ConnectionSecret,
                                            },
                                            Key: "database",
                                        },
                                    },
                                },
                            },
                            Ports: []corev1.ContainerPort{
                                {
                                    Name:          "mysql",
                                    ContainerPort: 3306,
                                },
                            },
                            VolumeMounts: []corev1.VolumeMount{
                                {
                                    Name:      "mysql-data",
                                    MountPath: "/var/lib/mysql",
                                },
                                {
                                    Name:      "schema",
                                    MountPath: "/docker-entrypoint-initdb.d",
                                },
                            },
                        },
                    },
                    Volumes: []corev1.Volume{
                        {
                            Name: "mysql-data",
                            VolumeSource: corev1.VolumeSource{
                                PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
                                    ClaimName: pvc.Name,
                                },
                            },
                        },
                        {
                            Name: "schema",
                            VolumeSource: corev1.VolumeSource{
                                ConfigMap: &corev1.ConfigMapVolumeSource{
                                    LocalObjectReference: corev1.LocalObjectReference{
                                        Name: "tokenshield-schema",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    }
    
    ctrl.SetControllerReference(ts, statefulSet, r.Scheme)
    
    if err := r.Create(ctx, statefulSet); err != nil && !errors.IsAlreadyExists(err) {
        return err
    }
    
    // Update component status
    ts.Status.Components.Database = "Ready"
    
    return nil
}

func (r *TokenShieldReconciler) reconcileTokenizer(ctx context.Context, ts *tokenizationv1alpha1.TokenShield) error {
    deployment := &appsv1.Deployment{
        ObjectMeta: metav1.ObjectMeta{
            Name:      "tokenshield-tokenizer",
            Namespace: ts.Namespace,
        },
        Spec: appsv1.DeploymentSpec{
            Replicas: &ts.Spec.Tokenizer.Replicas,
            Selector: &metav1.LabelSelector{
                MatchLabels: map[string]string{
                    "app":       "tokenshield",
                    "component": "tokenizer",
                },
            },
            Template: corev1.PodTemplateSpec{
                ObjectMeta: metav1.ObjectMeta{
                    Labels: map[string]string{
                        "app":       "tokenshield",
                        "component": "tokenizer",
                    },
                },
                Spec: corev1.PodSpec{
                    Containers: []corev1.Container{
                        {
                            Name:  "tokenizer",
                            Image: "tokenshield/unified-tokenizer:latest",
                            Env: []corev1.EnvVar{
                                {
                                    Name:  "TOKEN_FORMAT",
                                    Value: ts.Spec.Tokenization.Format,
                                },
                                {
                                    Name:  "USE_KEK_DEK",
                                    Value: fmt.Sprintf("%t", ts.Spec.Tokenization.Encryption.KekDek),
                                },
                                // Database connection from secret
                                {
                                    Name: "DB_HOST",
                                    ValueFrom: &corev1.EnvVarSource{
                                        SecretKeyRef: &corev1.SecretKeySelector{
                                            LocalObjectReference: corev1.LocalObjectReference{
                                                Name: ts.Spec.Database.ConnectionSecret,
                                            },
                                            Key: "host",
                                        },
                                    },
                                },
                                // ... more env vars
                            },
                            Ports: []corev1.ContainerPort{
                                {
                                    Name:          "http",
                                    ContainerPort: 8080,
                                },
                                {
                                    Name:          "icap",
                                    ContainerPort: 1344,
                                },
                                {
                                    Name:          "api",
                                    ContainerPort: 8090,
                                },
                            },
                            Resources: corev1.ResourceRequirements{
                                Requests: corev1.ResourceList{
                                    corev1.ResourceCPU:    resource.MustParse(ts.Spec.Tokenizer.Resources.Requests.CPU),
                                    corev1.ResourceMemory: resource.MustParse(ts.Spec.Tokenizer.Resources.Requests.Memory),
                                },
                                Limits: corev1.ResourceList{
                                    corev1.ResourceCPU:    resource.MustParse(ts.Spec.Tokenizer.Resources.Limits.CPU),
                                    corev1.ResourceMemory: resource.MustParse(ts.Spec.Tokenizer.Resources.Limits.Memory),
                                },
                            },
                        },
                    },
                },
            },
        },
    }
    
    ctrl.SetControllerReference(ts, deployment, r.Scheme)
    
    if err := r.Create(ctx, deployment); err != nil && !errors.IsAlreadyExists(err) {
        return err
    }
    
    // Create Service for tokenizer
    service := &corev1.Service{
        ObjectMeta: metav1.ObjectMeta{
            Name:      "tokenshield-tokenizer",
            Namespace: ts.Namespace,
        },
        Spec: corev1.ServiceSpec{
            Selector: map[string]string{
                "app":       "tokenshield",
                "component": "tokenizer",
            },
            Ports: []corev1.ServicePort{
                {
                    Name:       "http",
                    Port:       8080,
                    TargetPort: intstr.FromInt(8080),
                },
                {
                    Name:       "icap",
                    Port:       1344,
                    TargetPort: intstr.FromInt(1344),
                },
                {
                    Name:       "api",
                    Port:       8090,
                    TargetPort: intstr.FromInt(8090),
                },
            },
        },
    }
    
    ctrl.SetControllerReference(ts, service, r.Scheme)
    
    if err := r.Create(ctx, service); err != nil && !errors.IsAlreadyExists(err) {
        return err
    }
    
    ts.Status.Components.Tokenizer = "Ready"
    
    return nil
}

func (r *TokenShieldReconciler) SetupWithManager(mgr ctrl.Manager) error {
    return ctrl.NewControllerManagedBy(mgr).
        For(&tokenizationv1alpha1.TokenShield{}).
        Owns(&appsv1.Deployment{}).
        Owns(&appsv1.StatefulSet{}).
        Owns(&corev1.Service{}).
        Owns(&networkingv1.Ingress{}).
        Complete(r)
}