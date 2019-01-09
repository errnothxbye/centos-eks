# centos-eks
CentOS as a grunt/worker node to EKS

A step-by-step article which explains how to configure CentOS7 with CRI-o. More specifically  (runc) runtime 
for trusted container workloads and ClearContainers (cc-runtime) for untrusted workloads on EKS
can be sourced at the below link.

https://medium.com/errnothxbye/centos-7-with-cri-o-on-eks-ae9684aff764

# extras script
The script in *extras* directory fetches the table contents available via the available [URL](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html#AvailableIpPerENI) 
and generates a file with values that the kubelet can consume in order to set *--max-pods* argument properly

# docs folder
Contains the copy of the medium.com article, for your convenience.
