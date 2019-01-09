# CentOS 7 with CRI-o on EKS
A hands-on guide to configure CentOS 7 as a worker node to EKS using CRI-o runtime.

- [x] Updated for EKS 1.11.5 kubernetes version

There’s a small bonus at the end that builds on top of CRI-o. :wink:

## Foreword
Some steps have been inspired by the EKS custom [AMI guide](https://github.com/awslabs/amazon-eks-ami).

Creating an EKS cluster is a topic outside the scope of this article.

**You will need a running EKS cluster before you being performing steps outlined below.**

## Prerequisites
### The Setup
Instantiate a CentOS 7 AWS marketplace AMI.

* Place it in the existing EKS worker node AZ of your choice.
* Add to it any IAM roles associated with the existing EKS worker nodes. It would be extremely useful if these IAM roles, associated with the EKS worker nodes would allow worker nodes to list clusters (many of the following steps leverage this); i.e. _eks:ListClusters_
* Add to it any security groups associated with the existing EKS worker nodes.
* Add a TAG to it, in the format (replace **$MY_CLUSTER_NAME** with the actual name of the EKS cluster) _kubernetes.io/cluster/$MY_CLUSTER_NAME: owned_


#### Enable _ip_forwarding_

```bash
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf && sysctl -p
```

#### Set iptables default policy for the FORWARD chain to ACCEPT

```bash
iptables -P FORWARD ACCEPT
```

#### Update the OS

```bash
yum update -y
```

#### Install pre-requisite packages
> ruby + nokogiri will be needed for the POD calc script later on

```bash
yum install -y epel-release
yum install -y conntrack curl nfs-utils ntp socat unzip wget bsdtar ruby rubygem-nokogiri
```

#### Enable ntpd

```bash
systemctl enable ntpd
```

#### Install awscli

```bash
wget -qO- https://bootstrap.pypa.io/get-pip.py | python
pip install --upgrade awscli
```

> If everything’s ok, you should see that the awscli has been installed successfully.

### Export some variables
#### Grab local IPv4 address

```bash
LOCAL_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
```

#### Set kube-dns CLUSTER-IP

```bash
DNS_CLUSTER_IP=10.100.0.10
[[ $LOCAL_IP == 10.* ]] && DNS_CLUSTER_IP=172.20.0.10
```

#### Kubernetes and aws-iam-authenticator versions

```bash
K8S_VER=v1.11.5
HEPTIO_VER=1.11.5
```

#### Grab EKS region

```bash
MY_REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone | sed 's/\(.\)$//')
```

#### Grab EKS cluster name

```bash
EKS_CLUSTER_NAME=$(aws eks list-clusters --region=$MY_REGION --output text --query 'clusters')
```

#### Grab EKS control plane API endpoint

```bash
EKS_API_ENDPOINT=$(aws eks describe-cluster --region=$MY_REGION --name=$EKS_CLUSTER_NAME --output=text --query 'cluster.{endpoint: endpoint}')
```

#### Set CNI and CNI plugin versions

```bash
CNI_VERSION=${CNI_VERSION:-"v0.6.0"}
CNI_PLUGIN_VERSION=${CNI_PLUGIN_VERSION:-"v0.7.1"}
```

### CRI-o setup
#### Create a repo file

```bash
cat << EOF > /etc/yum.repos.d/crio.repo
[cri-o]
name=CRI-O Packages for EL 7 — $basearch
baseurl=https://cbs.centos.org/repos/paas7-crio-311-candidate/x86_64/os
enabled=1
gpgcheck=0
EOF
```

#### Install CRI-o runtime and tools

```bash
yum -y install cri-o cri-tools
```

#### Configure CRI-o

```bash
cat << EOF > /etc/crio/crio.conf
[crio]
storage_driver = "overlay2"
[crio.api]
listen = "/var/run/crio/crio.sock"
stream_address = ""
stream_port = "10010"
stream_enable_tls = false
stream_tls_cert = ""
stream_tls_key = ""
stream_tls_ca = ""
file_locking = false
[crio.runtime]
runtime = "/usr/bin/runc"
runtime_untrusted_workload = ""
default_workload_trust = "trusted"
no_pivot = false
conmon = "/usr/libexec/crio/conmon"
conmon_env = [
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
]
selinux = true
seccomp_profile = "/etc/crio/seccomp.json"
apparmor_profile = "crio-default"
cgroup_manager = "cgroupfs"
default_capabilities = [
    "CHOWN",
    "DAC_OVERRIDE",
    "FSETID",
    "FOWNER",
    "NET_RAW",
    "SETGID",
    "SETUID",
    "SETPCAP",
    "NET_BIND_SERVICE",
    "SYS_CHROOT",
    "KILL",
]
hooks_dir_path = "/usr/share/containers/oci/hooks.d"
default_mounts = [
    "/usr/share/rhel/secrets:/run/secrets",
]
pids_limit = 1024
log_size_max = -1
read_only = false
log_level = "error"
uid_mappings = ""
gid_mappings = ""
[crio.image]
default_transport = "docker://"
pause_image = "k8s.gcr.io/pause-amd64:3.1"
pause_command = "/pause"
signature_policy = ""
image_volumes = "mkdir"
registries = [
  "602401143452.dkr.ecr.$MY_REGION.amazonaws.com",
  "docker.io",
  "registry.hub.docker.com",
  "k8s.gcr.io",
]
[crio.network]
network_dir = "/etc/cni/net.d/"
plugin_dir = "/opt/cni/bin"
EOF
```

#### Remove CRI-o default CNI configuration

```bash
rm -rf /etc/cni/net.d/*
```

#### Enable CRI-o daemon

```bash
systemctl daemon-reload
systemctl enable crio
```

### Kubernetes setup
#### Create directories

```bash
mkdir -p /etc/kubernetes/{manifests,pki,kubelet}
mkdir -p /opt/cni/bin
```

#### Grab CNI

```bash
wget -qO- https://github.com/containernetworking/cni/releases/download/${CNI_VERSION}/cni-amd64-${CNI_VERSION}.tgz | bsdtar -xvf - -C /opt/cni/bin
```

#### Grab CNI plugins

```bash
wget -qO- https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGIN_VERSION}/cni-plugins-amd64-${CNI_PLUGIN_VERSION}.tgz | bsdtar -xvf - -C /opt/cni/bin
```

#### Grab kubelet and kubectl binaries

```bash
BIN_BASE_URL="https://storage.googleapis.com/kubernetes-release/release/$K8S_VER/bin/linux/amd64"
BINARIES=(
    kubelet
    kubectl
)
for binary in ${BINARIES[*]} ; do
    wget $BIN_BASE_URL/$binary -O /usr/bin/$binary
    chmod +x /usr/bin/$binary
done
```

#### Grab heptio IAM authenticator (aws-iam-authenticator)

```bash
wget https://amazon-eks.s3-us-west-2.amazonaws.com/$HEPTIO_VER/2018-12-06/bin/linux/amd64/aws-iam-authenticator -O /usr/bin/aws-iam-authenticator
chmod +x /usr/bin/aws-iam-authenticator
```

#### Fetch EKS CA

```bash
cat << EOF > /etc/kubernetes/pki/ca.crt
$(aws eks describe-cluster \
--region=$MY_REGION \
--name=$EKS_CLUSTER_NAME \
--output=text --query 'cluster.{certificateAuthorityData: certificateAuthority.data}' | base64 -d)
EOF
```

#### Create kubeconfig

```bash
cat << EOF > /etc/kubernetes/kubelet/kubeconfig
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority: /etc/kubernetes/pki/ca.crt
    server: $EKS_API_ENDPOINT
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: kubelet
  name: kubelet
current-context: kubelet
users:
- name: kubelet
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1alpha1
      command: /usr/bin/aws-iam-authenticator
      args:
        - "token"
        - "-i"
        - "$EKS_CLUSTER_NAME"
EOF
```

#### Generate POD per ENI file
With EKS you can only run a certain number of PODs per ENI on your worker nodes.

This script fetches the table contents available via the available [URL](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html#AvailableIpPerENI) and generates a file with values that the kubelet can consume in order to set _--max-pods_ argument properly

```bash
wget -qO- https://raw.githubusercontent.com/errnothxbye/centos-eks/master/extra/pods_per_eni.rb | ruby
```

> If everything’s ok, you should have a file _/etc/kubernetes/misc/eni-max-pods.txt_ generated with proper values.

#### Create kubelet config file (v1.11.5)

```bash
cat << EOF > /etc/kubernetes/kubelet/config
kind: KubeletConfiguration
apiVersion: kubelet.config.k8s.io/v1beta1
address: 0.0.0.0
authentication:
  anonymous:
    enabled: false
  webhook:
    cacheTTL: 2m0s
    enabled: true
  x509:
    clientCAFile: "/etc/kubernetes/pki/ca.crt"
authorization:
  mode: Webhook
  webhook:
    cacheAuthorizedTTL: 5m0s
    cacheUnauthorizedTTL: 30s
cgroupDriver: cgroupfs
clusterDomain: cluster.local
maxPods: $(grep $(curl -s http://169.254.169.254/latest/meta-data/instance-type) /etc/kubernetes/misc/eni-max-pods.txt | awk '{print $2}')
runtimeRequestTimeout: "10m"
kubeletCgroups: /system.slice
clusterDNS:
  - $DNS_CLUSTER_IP
featureGates:
  RotateKubeletServerCertificate: true
serverTLSBootstrap: true
EOF
```

#### Create kubelet service

```bash
cat << EOF > /etc/systemd/system/kubelet.service
[Unit]
Description=Kubernetes Kubelet
Documentation=https://github.com/kubernetes/kubernetes
After=crio.service
Requires=crio.service
[Service]
ExecStart=/usr/bin/kubelet \\
  --node-ip=$LOCAL_IP \\
  --config=/etc/kubernetes/kubelet/config \\
  --allow-privileged=true \\
  --cloud-provider=aws \\
  --container-runtime=remote \\
  --container-runtime-endpoint=unix:///var/run/crio/crio.sock \\
  --image-service-endpoint=unix:///var/run/crio/crio.sock \\
  --network-plugin=cni \\
  --root-dir=/etc/kubernetes/kubelet \\
  --cert-dir=/etc/kubernetes/kubelet/pki \\
  --register-node=true \\
  --kubeconfig=/etc/kubernetes/kubelet/kubeconfig \\
  --node-labels=runtime=crio
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
```

#### Enable and start kubelet

```bash
systemctl daemon-reload
systemctl enable kubelet
systemctl start kubelet
```

If everything's ok, in a couple of seconds you should see your CentOS 7 AMI with CRI-o latched onto EKS cluster.

```bash
kubectl get node --selector=runtime=crio
NAME                    STATUS    ROLES     AGE       VERSION
xxx.xxx.xxx.xxx         Ready     <none>    1m        v1.11.5
```

#### List containers on the node

Issue _crictl ps_ command

```bash
CONTAINER ID IMAGE CREATED STATE NAME ATTEMPT
fa25443c53ca6 602401143452.dkr.ecr.eu-west-1.amazonaws.com/amazon-k8s-cni@sha256:1fafb3a9a12feef7105986c0ed5e3a6b327f2b5a5356e64f026509614dab921d 23 hours ago Running aws-node 0
2e808c0d754ac c6fc6eef666a5ec079aa5249aacfa2443c96e06aa2b5d18e351d6cfff6c5f00c 23 hours ago Running kube-proxy
```

## Bonus!!
Enable [ClearContainers](https://clearlinux.org/containers) runtime (_cc-runtime_) as an untrusted workload runtime with CRI-o.

### Foreword
ClearContainers are extremely lightweight virtual machines that synergize well with the container ecosystem.

They run their own lightweight OS and dedicated kernel, providing isolation of network, I/O, memory and can also utilize hardware-enforced isolation with virtualization VT extensions.

### Prerequisites
Since they are extremely lightweight machines, you will need

* An instance type that has VT extensions; i.e. i3.metal
* All the previous steps for configuring a node with CRI-o runtime as EKS worker node apply.

### The setup
Instantiate an i3.metal machine with CentOS 7 as OS.

Follow the steps above to configure this instance as EKS worker node but stop before the CRI-o setup section/steps.

### Install ClearLinux containers 3.0
#### Grab cc repo

```bash
wget http://download.opensuse.org/repositories/home:/clearcontainers:/clear-containers-3/CentOS_7/home:clearcontainers:clear-containers-3.repo -O /etc/yum.repos.d/cc.repo
```

#### Install cc-runtime and relevant packages

```bash
yum -y install cc-* qemu-cc*
```

#### Configure clear-containers

```bash
sed -i 's/qemu-system-x86_64/qemu-cc-system-x86_64/g' /usr/share/defaults/clear-containers/configuration.toml
sed -i 's/macvlan/bridged/g' /usr/share/defaults/clear-containers/configuration.toml
```

#### Configure CRI-o
The only relevant change to the CRI-o config is adding _/usr/bin/cc-runtime_ as a value to _theruntime_untrusted_workload_ configuration option.

All other steps outlined in the article above, are the same.

For visibility and clarity, the complete here-doc is shown below (incl. _runtime_untrusted_workload_)

```bash
cat << EOF > /etc/crio/crio.conf
[crio]
storage_driver = "overlay2"
[crio.api]
listen = "/var/run/crio/crio.sock"
stream_address = ""
stream_port = "10010"
stream_enable_tls = false
stream_tls_cert = ""
stream_tls_key = ""
stream_tls_ca = ""
file_locking = false
[crio.runtime]
runtime = "/usr/bin/runc"
runtime_untrusted_workload = "/usr/bin/cc-runtime"
default_workload_trust = "trusted"
no_pivot = false
conmon = "/usr/libexec/crio/conmon"
conmon_env = [
 "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
]
selinux = true
seccomp_profile = "/etc/crio/seccomp.json"
apparmor_profile = "crio-default"
cgroup_manager = "cgroupfs"
default_capabilities = [
 "CHOWN",
 "DAC_OVERRIDE",
 "FSETID",
 "FOWNER",
 "NET_RAW",
 "SETGID",
 "SETUID",
 "SETPCAP",
 "NET_BIND_SERVICE",
 "SYS_CHROOT",
 "KILL",
]
hooks_dir_path = "/usr/share/containers/oci/hooks.d"
default_mounts = [
 "/usr/share/rhel/secrets:/run/secrets",
]
pids_limit = 1024
log_size_max = -1
read_only = false
log_level = "error"
uid_mappings = ""
gid_mappings = ""
[crio.image]
default_transport = "docker://"
pause_image = "k8s.gcr.io/pause-amd64:3.1"
pause_command = "/pause"
signature_policy = ""
image_volumes = "mkdir"
registries = [
 "602401143452.dkr.ecr.$MY_REGION.amazonaws.com",
 "docker.io",
 "registry.hub.docker.com",
 "k8s.gcr.io",
]
[crio.network]
network_dir = "/etc/cni/net.d/"
plugin_dir = "/opt/cni/bin"
EOF
```

#### Configure kubelet
For better granulation, add more labels to the i3.metal instance’s kubelet arguments.

```bash
--node-labels=runtime=crio,hw=metal,workload=untrusted
```

### Verify workloads
#### Trusted
Create a POD manifest and add a relevant annotation to have it ran by a _“trusted”_ **_runc_** runtime

```bash
apiVersion: v1
kind: Pod
metadata:
  name: nginx-trusted
  annotations:
    io.kubernetes.cri-o.TrustedSandbox: "true"
spec:
  containers:
  - name: nginx
    image: nginx:1.15.5
    ports:
    - containerPort: 80
  nodeSelector:
    hw: metal
```

#### Untrusted
Create a POD manifest and add a relevant annotation to have it ran by an _“untrusted”_ **_cc-runtime_** runtime

```bash
apiVersion: v1
kind: Pod
metadata:
  name: nginx-untrusted
  annotations:
    io.kubernetes.cri-o.TrustedSandbox: "false"
spec:
  containers:
  - name: nginx
    image: nginx:1.15.5
    ports:
    - containerPort: 80
  nodeSelector:
    hw: metal
```

Apply above manifest using kubectl command.

#### Verify your workloads (on the worker node)
Run _cc-runtime list_ command to get a list of untrusted container workloads running on the node

```bash
ID PID STATUS BUNDLE CREATED OWNER
1f1acc3a0595d49c0c93fb89a785c66b80fbe4c94331f25f20af7b6b8c589dcd 12292 running /run/containers/storage/overlay-containers/1f1acc3a0595d49c0c93fb89a785c66b80fbe4c94331f25f20af7b6b8c589dcd/userdata 2018–11–20T09:25:28.937418117Z #0
77730a648caafb727c2d6a2b52b8c28e9aef18e40e3b9c64f0524bef9f1a5fcf 12483 running /run/containers/storage/overlay-containers/77730a648caafb727c2d6a2b52b8c28e9aef18e40e3b9c64f0524bef9f1a5fcf/userdata 2018–11–20T09:25:34.671725933Z #0
```

Run _crictl ps_ command to get a list of all container workloads running on the node

```bash
CONTAINER ID        IMAGE                                                                                                                                 CREATED             STATE               NAME                ATTEMPT
77730a648caaf       docker.io/library/nginx@sha256:d98b66402922eccdbee49ef093edb2d2c5001637bd291ae0a8cd21bb4c36bebe                                       3 hours ago         Running             nginx               0
c47e18087a3b7       docker.io/library/nginx@sha256:d98b66402922eccdbee49ef093edb2d2c5001637bd291ae0a8cd21bb4c36bebe                                       3 hours ago         Running             nginx               0
fc5d666325e18       602401143452.dkr.ecr.eu-west-1.amazonaws.com/amazon-k8s-cni@sha256:1fafb3a9a12feef7105986c0ed5e3a6b327f2b5a5356e64f026509614dab921d   3 hours ago         Running             aws-node            0
0185c5f50f320       602401143452.dkr.ecr.eu-west-1.amazonaws.com/eks/kube-proxy@sha256:76927fb03bd6b37be4330c356e95bcac16ee6961a12da7b7e6ffa50db376438c   3 hours ago         Running             kube-proxy          0
```

You should see two nginx containers running on the node, verify their properties (replace **$NGINX_CONTAINER_ID** with the actual container ID running on your node)

```bash
# Trusted container sharing host's kernel
crictl exec -it $NGINX_CONTAINER_ID1 uname -r
3.10.0–862.14.4.el7.x86_64

# Untrusted container running its own kernel
crictl exec -it $NGINX_CONTAINER_ID2 uname -r
4.14.22-86.1.container
```
