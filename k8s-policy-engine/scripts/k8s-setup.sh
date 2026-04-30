#!/bin/bash
set -eo pipefail

echo "============================================"
echo " Kubernetes 1.32 Setup Script"
echo " Ubuntu 24.04 / root account"
echo "============================================"

# ─────────────────────────────────────────────
# 1. kubeadm, kubectl, kubelet 설치
# ─────────────────────────────────────────────
echo ""
echo "[1/8] kubeadm / kubectl / kubelet 설치 중..."

apt-get update -y
apt-get install -y apt-transport-https ca-certificates curl gpg

KUBE_KEYRING=/etc/apt/keyrings/kubernetes-apt-keyring.gpg
mkdir -p /etc/apt/keyrings

curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.32/deb/Release.key \
  | gpg --dearmor -o "$KUBE_KEYRING"

echo "deb [signed-by=${KUBE_KEYRING}] https://pkgs.k8s.io/core:/stable:/v1.32/deb/ /" \
  > /etc/apt/sources.list.d/kubernetes.list

apt-get update -y
apt-get install -y kubelet kubeadm kubectl
apt-mark hold kubelet kubeadm kubectl

echo "[1/8] 완료 - $(kubeadm version --output short 2>/dev/null || kubeadm version)"

# ─────────────────────────────────────────────
# 2. kubelet 서비스 활성화
# ─────────────────────────────────────────────
echo ""
echo "[2/8] kubelet 서비스 활성화 중..."
systemctl enable kubelet
echo "[2/8] 완료 - kubelet enabled"

# ─────────────────────────────────────────────
# 3. containerd 설정 수정 (SystemdCgroup = true)
# ─────────────────────────────────────────────
echo ""
echo "[3/8] containerd 설정 수정 중..."

CONTAINERD_CONFIG=/etc/containerd/config.toml
mkdir -p /etc/containerd

if [ ! -f "$CONTAINERD_CONFIG" ] || [ ! -s "$CONTAINERD_CONFIG" ]; then
  echo "  설정 파일 없음 → containerd config default 로 생성"
  containerd config default > "$CONTAINERD_CONFIG"
fi

# SystemdCgroup = false → true 로 교체
if grep -q "SystemdCgroup" "$CONTAINERD_CONFIG"; then
  sed -i 's/SystemdCgroup\s*=\s*false/SystemdCgroup = true/g' "$CONTAINERD_CONFIG"
else
  # runc options 섹션 아래에 직접 삽입
  sed -i '/\[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options\]/a\            SystemdCgroup = true' "$CONTAINERD_CONFIG"
fi

systemctl restart containerd
echo "[3/8] 완료 - SystemdCgroup = true 설정 및 containerd 재시작"

# ─────────────────────────────────────────────
# 4. swap 비활성화
# ─────────────────────────────────────────────
echo ""
echo "[4/8] swap 비활성화 중..."
swapoff -a
sed -i '/\bswap\b/ s/^\([^#]\)/#\1/' /etc/fstab
echo "[4/8] 완료 - swap off 및 /etc/fstab swap 라인 주석처리"

# ─────────────────────────────────────────────
# 5. kubeadm init
# ─────────────────────────────────────────────
echo ""
echo "[5/8] kubeadm init 실행 중..."

# 현재 서버의 기본 라우트에 연결된 IP 자동 감지
SERVER_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)
if [ -z "$SERVER_IP" ]; then
  SERVER_IP=$(hostname -I | awk '{print $1}')
fi
echo "  감지된 서버 IP: $SERVER_IP"

kubeadm init \
  --pod-network-cidr=10.244.0.0/16 \
  --apiserver-advertise-address="$SERVER_IP" \
  --kubernetes-version=v1.32.0 \
  2>&1 | tee /var/log/kubeadm-init.log
# set -o pipefail 적용으로 kubeadm 실패 시 자동 중단됨

echo "[5/8] 완료 - kubeadm init 성공 (로그: /var/log/kubeadm-init.log)"

# ─────────────────────────────────────────────
# 6. kubeconfig 설정 (root 계정)
# ─────────────────────────────────────────────
echo ""
echo "[6/8] kubeconfig 설정 중 (root 계정)..."
export KUBECONFIG=/etc/kubernetes/admin.conf

BASHRC_LINE='export KUBECONFIG=/etc/kubernetes/admin.conf'
if ! grep -qF "$BASHRC_LINE" ~/.bashrc; then
  echo "$BASHRC_LINE" >> ~/.bashrc
  echo "  ~/.bashrc 에 KUBECONFIG 추가"
else
  echo "  ~/.bashrc 에 이미 설정되어 있음"
fi
echo "[6/8] 완료"

# ─────────────────────────────────────────────
# 7. Flannel CNI 설치
# ─────────────────────────────────────────────
echo ""
echo "[7/8] Flannel CNI 설치 중..."

# API 서버가 완전히 준비될 때까지 대기 (최대 60초)
echo "  API 서버 준비 대기 중..."
for i in $(seq 1 12); do
  if kubectl get nodes &>/dev/null; then
    echo "  API 서버 응답 확인 (${i}번째 시도)"
    break
  fi
  echo "  대기 중... (${i}/12)"
  sleep 5
done

kubectl apply \
  -f https://raw.githubusercontent.com/flannel-io/flannel/v0.26.4/Documentation/kube-flannel.yml
echo "[7/8] 완료 - Flannel 배포됨"

# ─────────────────────────────────────────────
# 8. 완료 확인
# ─────────────────────────────────────────────
echo ""
echo "[8/8] 완료 확인 중 (노드/파드가 Ready 상태가 될 때까지 최대 90초 대기)..."
sleep 10

echo ""
echo "--- kubectl get nodes ---"
kubectl get nodes

echo ""
echo "--- kubectl get pods --all-namespaces ---"
kubectl get pods --all-namespaces

echo ""
echo "============================================"
echo " Kubernetes 1.32 설치 완료!"
echo " 서버 IP : $SERVER_IP"
echo " kubeconfig : /etc/kubernetes/admin.conf"
echo "============================================"
echo ""
echo "※ worker 노드 join 명령어:"
grep -A2 "kubeadm join" /var/log/kubeadm-init.log | tail -3
