// Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

const (
	SampleVulnerableHSKUBERNETES1 = `apiVersion: v1
kind: Pod
metadata:
  name: security-context-demo
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
	allowPrivilegeEscalation: true
  volumes:
  - name: sec-ctx-vol
    emptyDir: {}
  containers:
  - name: sec-ctx-demo
    image: busybox
    command: [ "sh", "-c", "sleep 1h" ]
    volumeMounts:
    - name: sec-ctx-vol
      mountPath: /data/demo`
	SampleVulnerableHSKUBERNETES2 = `
apiVersion: v1
kind: Pod
metadata:
  name: hostaliases-pod
spec:
  restartPolicy: Never
  hostAliases:
  - ip: "127.0.0.1"
    hostnames:
    - "foo.local"
    - "bar.local"
  - ip: "10.1.2.3"
    hostnames:
    - "foo.remote"
    - "bar.remote"
  containers:
  - name: cat-hosts
    image: busybox
    command:
    - cat
    args:
    - "/etc/hosts"
`
	SampleVulnerableHSKUBERNETES3 = `
apiVersion: v1
kind: Pod
metadata:
  name: volume-hostpath
spec:
  []...]
  volumes:
  - name: test-volume
    hostPath:
      path: /var/run/docker.sock
`
	SampleVulnerableHSKUBERNETES4 = `
---
apiVersion: extensions/v1beta1
kind: Deployment
...
      containers:
      - name: payment
        image: nginx
        securityContext:
          capabilities:
            drop: # Drop all capabilities from a pod as above
              - all
            add: # Add sys_admin is broken of security
              - SYS_ADMIN
`
	SampleVulnerableHSKUBERNETES5 = `
apiVersion: v1
kind: Pod
metadata:
  name: privileged
spec:
  containers:
    - name: pause
      image: k8s.gcr.io/pause
      # Security Context should not be use with privileged option enable
      securityContext:
        privileged: true
`
	SampleVulnerableHSKUBERNETES6 = `apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: privileged
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: unconfined
spec:
  privileged: true
  allowPrivilegeEscalation: true
  allowedCapabilities:
  - '*'
  volumes:
  - '*'
  hostNetwork: true
  hostPorts:
  - min: 0
    max: 65535
  hostIPC: true
  hostPID: true
  runAsUser:
    rule: 'RunAsAny'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
`
	SampleVulnerableHSKUBERNETES7 = `apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: privileged
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: '*'
spec:
  hostPorts:
  - min: 0
    max: 65535
  hostIPC: true
`
	SampleVulnerableHSKUBERNETES8 = `apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: privileged
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: '*'
spec:
  hostPorts:
  - min: 0
    max: 65535
  hostPID: true
`
	SampleVulnerableHSKUBERNETES9 = `
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: privileged
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: unconfined
spec:
  hostPorts:
  - min: 0
    max: 65535
  hostNetwork: true
`
)

const (
	SampleSafeHSKUBERNETES1 = `apiVersion: v1
kind: Pod
metadata:
  name: security-context-demo
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
  volumes:
  - name: sec-ctx-vol
    emptyDir: {}
  containers:
  - name: sec-ctx-demo
    image: busybox
    command: [ "sh", "-c", "sleep 1h" ]
    volumeMounts:
    - name: sec-ctx-vol
      mountPath: /data/demo`
	SampleSafeHSKUBERNETES2 = `
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: example-ingress
  annotations:
    ingress.kubernetes.io/rewrite-target: /
spec:
  rules:
  - http:
      paths:
        - path: /foo
          backend:
            serviceName: foo-service
            servicePort: 8000
        - path: /bar
          backend:
            serviceName: bar-service
            servicePort: 8000
`
	SampleSafeHSKUBERNETES3 = `
apiVersion: v1  
kind: Pod  
metadata:  
  name: security-best-practice
spec:  
  containers:  
  # specification of the pod’s containers  
  # ...  
  securityContext:  
    readOnlyRootFilesystem: true
`
	SampleSafeHSKUBERNETES4 = `
---
apiVersion: extensions/v1beta1
kind: Deployment
...
      containers:
      - name: payment
        image: nginx
        securityContext:
          capabilities:
            drop: # Drop all capabilities from a pod as above
              - all
            add: # Add only those required
              - NET_BIND_SERVICE
`
	SampleSafeHSKUBERNETES5 = `
apiVersion: v1
kind: Pod
metadata:
  name: privileged
spec:
  containers:
    - name: pause
      image: k8s.gcr.io/pause
      securityContext:
        privileged: false
`
	SampleSafeHSKUBERNETES6 = `apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: privileged
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: 'runtime/default'
spec:
  privileged: true
  allowPrivilegeEscalation: true
  allowedCapabilities:
  - '*'
  volumes:
  - '*'
  hostNetwork: true
  hostPorts:
  - min: 0
    max: 65535
  hostIPC: true
  hostPID: true
  runAsUser:
    rule: 'RunAsAny'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
`
	SampleSafeHSKUBERNETES7 = `apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: privileged
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: '*'
spec:
  hostPorts:
  - min: 0
    max: 65535
  hostIPC: false
`
	SampleSafeHSKUBERNETES8 = `apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: privileged
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: '*'
spec:
  hostPorts:
  - min: 0
    max: 65535
  hostPID: false`
	SampleSafeHSKUBERNETES9 = `
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: privileged
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: unconfined
spec:
  hostPorts:
  - min: 0
    max: 65535
  hostNetwork: false
`
)
