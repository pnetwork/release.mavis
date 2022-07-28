#!/bin/sh
set -e
# Docker CE for Linux installation script
# SCRIPT_COMMIT_SHA="b2e29ef7a9a89840d2333637f7d1900a83e7153f"
TAG=preview-apiserver
MAVIS_VERSION="1.0.0"
MAVIS_REPO=cr-preview.pentium.network/mavisdev
VERSION="20.10"
CHANNEL="stable"
DOWNLOAD_URL="https://download.docker.com"
REPO_FILE="docker-ce.repo"
COLOR_REST='\e[0m'
COLOR_GREEN='\e[0;32m'
COLOR_RED='\e[0;31m'
INSTALL_DIR="/opt/mavis"
# Mavis Directory Structure
DIR_LIST="
backups
data/maindb
data/ssh-proxy
data/rdp-proxy
data/media/recordings
data/cache
logs
bin
config/${MAVIS_VERSION}
"

DRY_RUN=${DRY_RUN:-}
while [ $# -gt 0 ]; do
	case "$1" in
	--dry-run)
		DRY_RUN=1
		;;
	--*)
		echo "Illegal option $1"
		;;
	esac
	shift $(($# > 0 ? 1 : 0))
done

command_exists() {
	which "$@" >/dev/null 2>&1
}

is_dry_run() {
	if [ -z "$DRY_RUN" ]; then
		return 1
	else
		return 0
	fi
}

check_user() {
	user="$(id -un 2>/dev/null || true)"
	sh_c='sh -c'
	if [ "$user" != 'root' ]; then
		if command_exists sudo; then
			sh_c='sudo -E sh -c'
		elif command_exists su; then
			sh_c='su -c'
		else
			cat >&2 <<-'EOF'
				Error: this installer needs the ability to run commands as root.
				We are unable to find either "sudo" or "su" available to make this happen.
			EOF
			exit 1
		fi
	fi
	if is_dry_run; then
		sh_c="echo"
	fi

}



check_environment() {

	## Check disk space (40GB)
	local avail_disk=$(df | grep "/$" | awk '{print $4}')
	if [ "$avail_disk" -lt 41943040 ]; then
		echo -e "${COLOR_RED}disk space is not enough to isntall mavis${COLOR_REST}"
		exit 1
	else
		echo -e "${COLOR_GREEN}check disk size ok${COLOR_REST}"
	fi
	## Check systemd exists
	if ! command_exists systemctl; then
		echo -e "${COLOR_RED}systemctl command not found${COLOR_REST}"
		echo -e "${COLOR_RED}ERROR: Mavis does not support operating systems without systemd${COLOR_REST}"
		exit 1
	else
		echo -e "${COLOR_GREEN}check systemd ok${COLOR_REST}"
	fi
	## Check CPU
	local cpu_total="$(lscpu | grep '^CPU(s):' | awk '{print $2}')"
	if [ "$cpu_total" -lt 4 ]; then
		echo -e "${COLOR_RED}CPU core is not enough to isntall mavis${COLOR_REST}"
		exit 1
	else
		echo -e "${COLOR_GREEN}check cpu ok${COLOR_REST}"
	fi
	## Check memory
	local avail_mem="$(free -g | grep Mem | awk '{print $2}')"
	if [ "$avail_mem" -lt 16 ]; then
		echo -e "${COLOR_RED}Memory is not enough to isntall mavis${COLOR_REST}"
		exit 1
	else
		echo -e "${COLOR_GREEN}check memory ok${COLOR_REST}"
	fi
	## Check Network
	case "$(curl -s --max-time 2 -I ${DOWNLOAD_URL} | sed 's/^[^ ]*  *\([0-9]\).*/\1/; 1q')" in
	[23])
		echo -e "${COLOR_GREEN}Check HTTP connectivity is up${COLOR_REST}"
		;;
	5)
		echo -e "${COLOR_RED}Can not connect to ${DOWNLOAD_URL}${COLOR_REST}"
		echo -e "${COLOR_RED}Check network status failed${COLOR_REST}"
		;;
	*)
		echo -e "The network is down or very slow"
		echo -e "${COLOR_RED}check network status failed${COLOR_REST}"
		;;
	esac
}

keeper_cli() {
	result=$(${sh_c} "docker run --rm -v  ${INSTALL_DIR}:${INSTALL_DIR} -v /var/run/docker.sock:/var/run/docker.sock -e CURRENT_VERSION=${MAVIS_VERSION} ${MAVIS_REPO}/keeper:${MAVIS_VERSION} ${1} ${2} ${3} ")
	if echo "${result}" |grep "Not Found";then
		echo -e "${COLOR_RED} ${2} create failed ${COLOR_REST}"
		exit 1
	elif [ -z "$result" ];then
		echo -e "${COLOR_RED} ${2} create failed ${COLOR_REST}"
		exit 1
	fi
	echo "${result}"
}

install_mavis() {

	## check config dir if exist
	if [ -d "${INSTALL_DIR}/config" ]; then
		echo -e "${COLOR_GREEN}Path ${INSTALL_DIR}/config is already exist${COLOR_REST}"
		$sh_c "mv -b ${INSTALL_DIR}/config ${INSTALL_DIR}/backups/config-$(date +'%Y-%m-%d-%H-%M:')"
	fi

	## Get MAVIS_URL
	if [ -z "$MAVIS_URL" ]; then
		local PUBLIC_IP=$(hostname -I | grep -v -E '^(192\.168|10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.)' | awk '{print $1}')
		MAVIS_URL="${PUBLIC_IP}"
		if [ -z "$PUBLIC_IP" ]; then
			MAVIS_URL="$(ip route get 1 | awk '{gsub(".*src",""); print $1; exit}')"
		fi
	fi

	## Get PostgreSQL
	if [ -z "$POSTGRES_PASSWORD" ]; then
		POSTGRES_PASSWORD=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 13)
	fi
	## Get KEYS

	MASTER_KEYS=${MASTER_KEYS:-$(keeper_cli generate-key MASTER_KEYS)}
	SECRET_KEY=${SECRET_KEY:-$(keeper_cli generate-key SECRET_KEY)}
	GATEWAY_CLIENT_ID=${GATEWAY_CLIENT_ID:-$(keeper_cli generate-key GATEWAY_CLIENT_ID)}
	GATEWAY_CLIENT_SECRET=${GATEWAY_CLIENT_SECRET:-$(keeper_cli generate-key GATEWAY_CLIENT_SECRET)}

	# Generate Directory Structure
	for i in ${DIR_LIST}; do
		$sh_c "mkdir -p ${INSTALL_DIR}/$i"
	done
	$sh_c "touch ${INSTALL_DIR}/config/current_version ${INSTALL_DIR}/config/old_version"
	$sh_c "echo ${MAVIS_VERSION} > ${INSTALL_DIR}/config/current_version"
	$sh_c "chown -R ${user}:${user} ${INSTALL_DIR}"
	cat >${INSTALL_DIR}/config/${MAVIS_VERSION}/docker-compose.yml <<EOF
version: "3.3"

x-logging:
  &dev-logging
  driver: journald

services:
  traefik:
    image: "cr.pentium.network/mavis/traefik:v2.6.1"
    container_name: "traefik"
    logging: *dev-logging
    command:
      - "--log.level=DEBUG"
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--providers.file.filename=/configuration/certificates.yaml"
      - "--entrypoints.websecure.address=:443"
    ports:
      - "8080:8080"
      - "443:443"
    networks:
      - mavis
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
#      - "./configuration/:/configuration/"


  mavis-apiserver:
    image: ${MAVIS_REPO}/apiserver:${TAG}
    container_name: mavis-apiserver
    depends_on:
      - mavis-postgres
    env_file:
      - ../.env
    ports:
      - "8000"
    networks:
      - mavis
    command: "uvicorn mavis.apiserver.main:app --host 0.0.0.0 --port 8000"
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.mavis-apiserver.service=mavis-apiserver@docker"
      - "traefik.http.services.mavis-apiserver.loadbalancer.server.port=8000"
      - "traefik.http.routers.mavis-apiserver.rule=Host(\`${MAVIS_URL}\`) && (PathPrefix(\`/api\`) || PathPrefix(\`/admin\`) || PathPrefix(\`/apistatic\`) || PathPrefix(\`/docs\`) || PathPrefix(\`/openapi.json\`) || PathPrefix(\`/auth\`) || PathPrefix(\`/redoc\`))"
      - "traefik.http.routers.mavis-apiserver.entrypoints=websecure"
      - "traefik.http.routers.mavis-apiserver.priority=2"
      - "traefik.http.routers.mavis-apiserver.tls=true"

  mavis-f2e:
    image: ${MAVIS_REPO}/f2e:${TAG}
    container_name: mavis-f2e
    depends_on:
      - mavis-apiserver
    env_file:
      - ../.env
    networks:
      - mavis
    expose:
      - "3000"
    volumes:
      - ./sshrec:/usr/share/nginx/html/assets/videos/sshrec:z
      - ./rdprec:/usr/share/nginx/html/assets/videos/rdprec:z
    logging: *dev-logging
    labels:
      - "traefik.enable=true"
      - "traefik.http.services.mavis-f2e.loadbalancer.server.port=3000"
      - "traefik.http.routers.mavis-f2e.rule=Host(\`${MAVIS_URL}\`)"
      - "traefik.http.routers.mavis-f2e.entrypoints=websecure"
      - "traefik.http.routers.mavis-f2e.service=mavis-f2e@docker"
      - "traefik.http.routers.mavis-f2e.priority=1"
      - "traefik.http.routers.mavis-f2e.tls=true"

  mavis-postgres:
    image: cr-preview.pentium.network/mavis/postgres:12.3
    container_name: mavis-postgres
    volumes:
      - ./db/data:/var/lib/postgresql/data:Z
      - ./db/backups:/backups:z
    env_file:
      - ../.env
    networks:
      - mavis
    logging: *dev-logging

  mavis-sshserver:
    image: ${MAVIS_REPO}/sshserver:${TAG}
    container_name: mavis-sshserver
    depends_on:
      - mavis-postgres
      - mavis-apiserver
    env_file:
      - ../.env
    networks:
      - mavis
    expose:
      - "4002"
    volumes:
      - ./sshrec:/tmp/sshrec:z
    logging: *dev-logging
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.mavis-sshserver.service=mavis-sshserver@docker"
      - "traefik.http.services.mavis-sshserver.loadbalancer.server.port=4002"
      - "traefik.http.routers.mavis-sshserver.rule=Host(\`${MAVIS_URL}\`) && PathPrefix(\`/ssh\`)"
      - "traefik.http.routers.mavis-sshserver.entrypoints=websecure"
      - "traefik.http.routers.mavis-sshserver.priority=3"
      - "traefik.http.routers.mavis-sshserver.tls=true"

  mavis-rdpguacd:
    image: ${MAVIS_REPO}/rdpguacd:${TAG}
    container_name: mavis-rdpguacd
    env_file:
      - ../.env
    networks:
      - mavis
    expose:
      - "4822"
    volumes:
      - ./rdprec:/tmp/rdprec:z
    logging: *dev-logging

  mavis-rdpwsserver:
    image: ${MAVIS_REPO}/rdpwsserver:${TAG}
    container_name: mavis-rdpwsserver
    depends_on:
      - mavis-postgres
      - mavis-apiserver
      - mavis-rdpguacd
    env_file:
      - ../.env
    networks:
      - mavis
    expose:
      - "4003"
    logging: *dev-logging
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.mavis-rdpwsserver.service=mavis-rdpwsserver@docker"
      - "traefik.http.services.mavis-rdpwsserver.loadbalancer.server.port=4003"
      - "traefik.http.routers.mavis-rdpwsserver.rule=Host(\`${MAVIS_URL}\`) && PathPrefix(\`/rdp\`)"
      - "traefik.http.routers.mavis-rdpwsserver.entrypoints=websecure"
      - "traefik.http.routers.mavis-rdpwsserver.priority=2"
      - "traefik.http.routers.mavis-rdpwsserver.tls=true"

  mavis-rdpguacenc:
    image: ${MAVIS_REPO}/rdpguacenc:${TAG}
    container_name: mavis-rdpguacenc
    depends_on:
      - mavis-rdpguacd
    env_file:
      - ../.env
    networks:
      - mavis
    volumes:
      - ./rdprec:/tmp/rdprec:z
    logging: *dev-logging

  mavis-pgweb:
    container_name: mavis-pgweb
    restart: always
    image: cr-preview.pentium.network/mavis/sosedoff/pgweb
    links:
      - mavis-postgres:postgres
    env_file:
      - ../.env
    depends_on:
      - mavis-postgres
    networks:
      - mavis
    expose:
      - "8081"
    logging: *dev-logging
    labels:
      - "traefik.enable=true"
      - "traefik.http.services.mavis-pgweb.loadbalancer.server.port=8081"
      - "traefik.http.routers.mavis-pgweb.rule=Host(\`pgweb.${MAVIS_URL}\`)"
      - "traefik.http.routers.mavis-pgweb.entrypoints=websecure"
      - "traefik.http.routers.mavis-pgweb.service=mavis-pgweb@docker"
      - "traefik.http.routers.mavis-pgweb.tls=true"

  mavis-redis:
    image: cr-preview.pentium.network/mavis/redis:5.0
    container_name: mavis-redis
    networks:
      - mavis
    logging: *dev-logging

  mavis-task-runner:
    image: ${MAVIS_REPO}/apiserver:${TAG}
    container_name: mavis-task-runner
    volumes:
      - ./logs/scripts:/app/logs/scripts:Z
      - ./logs:/app/logs
    depends_on:
      - mavis-redis
      - mavis-postgres
    env_file:
      - ../.env
    ports: []
    command: "celery -A mavis.apiserver.main.celery_app worker --loglevel=info"
    networks:
      - mavis
    logging: *dev-logging
    labels:
      - "traefik.enable=false"

  mavis-beat:
    image: ${MAVIS_REPO}/apiserver:${TAG}
    container_name: mavis-beat
    depends_on:
      - mavis-redis
      - mavis-postgres
    env_file:
      - ../.env
    ports: []
    command: "celery --app=mavis.apiserver.main.celery_app beat -l info"
    networks:
      - mavis
    logging: *dev-logging
    labels:
      - "traefik.enable=false"

  mavis-flower:
    image: ${MAVIS_REPO}/apiserver:${TAG}
    container_name: mavis-flower
    depends_on:
      - mavis-postgres
    env_file:
      - ../.env
    expose:
      - "5555"
    command: ["celery", "flower", "--app=mavis.apiserver.main.celery_app", "--broker=${CELERY_BROKER_URL}",
     "--basic_auth=${CELERY_FLOWER_USER}:${CELERY_FLOWER_PASSWORD}"]
    networks:
      - mavis
    logging: *dev-logging
    labels:
      - "traefik.enable=true"
      - "traefik.http.services.mavis-flower.loadbalancer.server.port=5555"
      - "traefik.http.routers.mavis-flower.rule=Host(\`flower.${MAVIS_URL}\`)"
      - "traefik.http.routers.mavis-flower.entrypoints=websecure"
      - "traefik.http.routers.mavis-flower.middlewares=inner-ip@file,admin-auth@docker"
      - "traefik.http.routers.mavis-flower.service=mavis-flower@docker"
      - "traefik.http.routers.mavis-flower.tls.certresolver=letsencrypt"


networks:
  mavis:
    name: mavis

EOF
	cat >${INSTALL_DIR}/config/.env <<EOF
MASTER_KEYS=${MASTER_KEYS}
MAVIS_URL=http://${MAVIS_URL}
SECRET_KEY=${SECRET_KEY}
MEDIA_STORE_PATH=${MEDIA_STORE_PATH:-${INSTALL_DIR}/data/media}
SSH_RECORDING_PATH=${SSH_RECORDING_PATH:-${INSTALL_DIR}/data/ssh-proxy}
SSH_RECORDING_SIZE=${SSH_RECORDING_SIZE:-50MB}
RDP_RECORDING_PATH=${RDP_RECORDING_PATH:-${INSTALL_DIR}/data/ssh-proxy}
GUACD_HOST=${GUACD_HOST:-mavis-rdpguacd}
GUACD_PORT=${GUACD_PORT:-4822}
REDIS_HOST=${REDIS_HOST:-mavis-redis}
REDIS_PORT=${REDIS_PORT:-6379}
REDIS_URL=redis://${REDIS_HOST:-mavis-redis}:${REDIS_PORT:-6379}/0
POSTGRES_HOST=${POSTGRES_HOST:-mavis-postgres}
POSTGRES_PORT=${POSTGRES_PORT:-5432}
POSTGRES_DB=${POSTGRES_DB:-mavis}
POSTGRES_USER=${POSTGRES_USER:-psql}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
DATABASE_URL=postgresql://${POSTGRES_USER:-psql}:${POSTGRES_PASSWORD}@${POSTGRES_HOST:-mavis-postgres}:${POSTGRES_PORT:-5432}/${POSTGRES_DB:-mavis}?sslmode=disable
DB_URL=postgresql://${POSTGRES_USER:-psql}:${POSTGRES_PASSWORD}@${POSTGRES_HOST:-mavis-postgres}:${POSTGRES_PORT:-5432}/${POSTGRES_DB:-mavis}
SMTP_HOST=${SMTP_HOST}
SMTP_PORT=${SMTP_PORT:-465}
SMTP_IS_SSL=${SMTP_IS_SSL:-true}
SMTP_SENDER_ACCOUNT=${SMTP_SENDER_ACCOUNT}
SMTP_SENDER_PASSWORD=${SMTP_SENDER_PASSWORD}
GATEWAY_CLIENT_ID=${GATEWAY_CLIENT_ID}
GATEWAY_CLIENT_SECRET=${GATEWAY_CLIENT_SECRET}
EOF
	cat >mavis.service <<EOF
[Unit]
Description=Service for mavis
Requires=docker.service
After=docker.service

[Service]
Environment=COMPOSE_HTTP_TIMEOUT=600
ExecStartPre=/bin/sh -c "/usr/bin/docker network create --driver bridge mavis || /bin/true"
ExecStartPre=/bin/sh -c "/usr/bin/docker rm keeper --force || /bin/true"
ExecStartPre=/bin/sh -c "/usr/bin/docker pull cr-preview.pentium.network/keeper:\$(cat ${INSTALL_DIR}/config/current_version)"
ExecStart=/bin/sh -c "/usr/bin/docker run --rm --log-driver=journald --name=keeper --net=mavis -v /var/run/docker.sock:/var/run/docker.sock -v ${INSTALL_DIR}:${INSTALL_DIR} -e INSTALL_DIR=${INSTALL_DIR} cr-preview.pentium.network/keeper:\$(cat ${INSTALL_DIR}/config/current_version) start"
ExecStop=/bin/sh -c "/usr/bin/docker run --rm --log-driver=journald --name=terminator --net=mavis -v /var/run/docker.sock:/var/run/docker.sock -v ${INSTALL_DIR}:${INSTALL_DIR} -e INSTALL_DIR=${INSTALL_DIR} cr-preview.pentium.network/keeper:\$(cat ${INSTALL_DIR}/config/current_version) stop"
StandardOutput=syslog
Restart=always
Type=simple
SuccessExitStatus=137
EOF
	$sh_c 'mv mavis.service /etc/systemd/system/mavis.service'
	# start mavis
	$sh_c 'systemctl daemon-reload'
	$sh_c 'systemctl start mavis'
	$sh_c 'systemctl enable mavis'

}

remove_docker() {
	echo "Removing old docker"
	check_user
	get_distribution
	$sh_c 'systemctl stop docker.service' || true
	$sh_c 'systemctl stop docker.socket' || true
	$sh_c 'systemctl stop mavis' || true
	case "$lsb_dist" in
	ubuntu | debian)
		$sh_c 'apt purge docker-ce docker-ce-cli containerd.io docker-compose-plugin docker docker-engine docker.io containerd runc docker-ce-rootless-extras -y'
		$sh_c 'rm -f /etc/apt/keyrings/docker.gpg'
		if command_exists docker; then
			echo -e "${COLOR_RED}If you already have Docker installed, please remove it${COLOR_REST}"
			exit 1
		fi
		;;
	centos | rhel)
		$sh_c 'yum remove docker-ce docker-ce-cli containerd.io docker-compose-plugin -y'
		if command_exists docker; then
			echo -e "${COLOR_RED}If you already have Docker installed, please remove it${COLOR_REST}"
			exit 1
		fi
		;;
	fedora)
		$sh_c 'dnf remove docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-selinux docker-engine-selinux docker-engine docker-logrotate  docker-ce docker-ce-cli containerd.io docker-compose-plugin -y'
		if command_exists docker; then
			echo -e "${COLOR_RED}If you already have Docker installed, please remove it${COLOR_REST}"
			exit 1
		fi
		;;
	zypper)
		$sh_c 'systemctl stop docker.service' || true
		$sh_c 'systemctl stop docker.socket' || true
		$sh_c 'systemctl stop mavis' || true
		$sh_c 'zypper remove docker-ce docker-ce-cli containerd.io docker-compose-plugin -y'
		if command_exists docker; then
			echo "${COLOR_RED}If you already have Docker installed, please remove it${COLOR_REST}"
			exit 1
		fi
		;;
	*) ;;

	esac
	echo "Remove old docker success"
}

start_docker() {
	if [ -d '/run/systemd/system' ]; then
		$sh_c 'systemctl daemon-reload'
		$sh_c 'systemctl start docker.service'
		$sh_c 'systemctl enable docker'
	else
		$sh_c 'service docker start'
		$sh_c 'service docker enable'
	fi
}

# version_gte checks if the version specified in $VERSION is at least
# the given CalVer (YY.MM) version. returns 0 (success) if $VERSION is either
# unset (=latest) or newer or equal than the specified version. Returns 1 (fail)
# otherwise.
#
# examples:
#
# VERSION=20.10
# version_gte 20.10 // 0 (success)
# version_gte 19.03 // 0 (success)
# version_gte 21.10 // 1 (fail)
version_gte() {
	if [ -z "$VERSION" ]; then
		return 0
	fi
	eval calver_compare "$VERSION" "$1"
}

# calver_compare compares two CalVer (YY.MM) version strings. returns 0 (success)
# if version A is newer or equal than version B, or 1 (fail) otherwise. Patch
# releases and pre-release (-alpha/-beta) are not taken into account
#
# examples:
#
# calver_compare 20.10 19.03 // 0 (success)
# calver_compare 20.10 20.10 // 0 (success)
# calver_compare 19.03 20.10 // 1 (fail)
calver_compare() (
	set +x

	yy_a="$(echo "$1" | cut -d'.' -f1)"
	yy_b="$(echo "$2" | cut -d'.' -f1)"
	if [ "$yy_a" -lt "$yy_b" ]; then
		return 1
	fi
	if [ "$yy_a" -gt "$yy_b" ]; then
		return 0
	fi
	mm_a="$(echo "$1" | cut -d'.' -f2)"
	mm_b="$(echo "$2" | cut -d'.' -f2)"
	if [ "${mm_a#0}" -lt "${mm_b#0}" ]; then
		return 1
	fi

	return 0
)

is_wsl() {
	case "$(uname -r)" in
	*microsoft*) true ;; # WSL 2
	*Microsoft*) true ;; # WSL 1
	*) false ;;
	esac
}

is_darwin() {
	case "$(uname -s)" in
	*darwin*) true ;;
	*Darwin*) true ;;
	*) false ;;
	esac
}

deprecation_notice() {
	distro=$1
	distro_version=$2
	echo
	printf "\033[91;1mDEPRECATION WARNING\033[0m\n"
	printf "    This Linux distribution (\033[1m%s %s\033[0m) reached end-of-life and is no longer supported by this script.\n" "$distro" "$distro_version"
	echo "    No updates or security fixes will be released for this distribution, and users are recommended"
	echo "    to upgrade to a currently maintained version of $distro."
	echo
	printf "Press \033[1mCtrl+C\033[0m now to abort this script, or wait for the installation to continue."
	echo
	sleep 10
}

get_distribution() {
	lsb_dist=""
	# Every system that we officially support has /etc/os-release
	if [ -r /etc/os-release ]; then
		lsb_dist="$(. /etc/os-release && echo "$ID")"
	fi
	# Returning an empty string here should be alright since the
	# case statements don't act unless you provide an actual value
	echo "$lsb_dist"
}

echo_docker_as_nonroot() {
	if is_dry_run; then
		return
	fi
	if command_exists docker && [ -e /var/run/docker.sock ]; then
		(
			set -x
			$sh_c 'docker version'
			$sh_c 'docker-compose version'
		) || true
	fi

	# intentionally mixed spaces and tabs here -- tabs are stripped by "<<-EOF", spaces are kept in the output
	echo
	echo "================================================================================"
	echo
	if version_gte "20.10"; then
		echo "To run Docker as a non-privileged user, consider setting up the"
		echo "Docker daemon in rootless mode for your user:"
		echo
		echo "    dockerd-rootless-setuptool.sh install"
		echo
		echo "Visit https://docs.docker.com/go/rootless/ to learn about rootless mode."
		echo
	fi
	echo
	echo "To run the Docker daemon as a fully privileged service, but granting non-root"
	echo "users access, refer to https://docs.docker.com/go/daemon-access/"
	echo
	echo "WARNING: Access to the remote API on a privileged Docker daemon is equivalent"
	echo "         to root access on the host. Refer to the 'Docker daemon attack surface'"
	echo "         documentation for details: https://docs.docker.com/go/attack-surface/"
	echo
	echo "================================================================================"
	echo
}

# Check if this is a forked Linux distro
check_forked() {

	# Check for lsb_release command existence, it usually exists in forked distros
	if command_exists lsb_release; then
		# Check if the `-u` option is supported
		set +e
		lsb_release -a -u >/dev/null 2>&1
		lsb_release_exit_code=$?
		set -e

		# Check if the command has exited successfully, it means we're in a forked distro
		if [ "$lsb_release_exit_code" = "0" ]; then
			# Print info about current distro
			cat <<-EOF
				You're using '$lsb_dist' version '$dist_version'.
			EOF

			# Get the upstream release info
			lsb_dist=$(lsb_release -a -u 2>&1 | tr '[:upper:]' '[:lower:]' | grep -E 'id' | cut -d ':' -f 2 | tr -d '[:space:]')
			dist_version=$(lsb_release -a -u 2>&1 | tr '[:upper:]' '[:lower:]' | grep -E 'codename' | cut -d ':' -f 2 | tr -d '[:space:]')

			# Print info about upstream distro
			cat <<-EOF
				Upstream release is '$lsb_dist' version '$dist_version'.
			EOF
		else
			if [ -r /etc/debian_version ] && [ "$lsb_dist" != "ubuntu" ] && [ "$lsb_dist" != "raspbian" ]; then
				if [ "$lsb_dist" = "osmc" ]; then
					# OSMC runs Raspbian
					lsb_dist=raspbian
				else
					# We're Debian and don't even know it!
					lsb_dist=debian
				fi
				dist_version="$(sed 's/\/.*//' /etc/debian_version | sed 's/\..*//')"
				case "$dist_version" in
				11)
					dist_version="bullseye"
					;;
				10)
					dist_version="buster"
					;;
				9)
					dist_version="stretch"
					;;
				8)
					dist_version="jessie"
					;;
				esac
			fi
		fi
	fi
}

do_install() {
	echo "# Executing docker install script"

	if command_exists docker; then
		cat >&2 <<-'EOF'
			Warning: the "docker" command appears to already exist on this system.

			If you already have Docker installed, this script can cause trouble, which is
			why we're displaying this warning and provide the opportunity to cancel the
			installation.

			If you installed the current Docker package using this script and are using it
			again to update Docker, you can safely ignore this message.

			You may press Ctrl+C now to abort this script.
		EOF
		(
			set -x
			sleep 20
		)
	fi

	check_user

	# perform some very rudimentary platform detection
	lsb_dist=$(get_distribution)
	lsb_dist="$(echo "$lsb_dist" | tr '[:upper:]' '[:lower:]')"

	if is_wsl; then
		echo
		echo "WSL DETECTED: We recommend using Docker Desktop for Windows."
		echo "Please get Docker Desktop from https://www.docker.com/products/docker-desktop"
		echo
		cat >&2 <<-'EOF'

			You may press Ctrl+C now to abort this script.
		EOF
		exit 1
	fi

	case "$lsb_dist" in

	ubuntu)
		if command_exists lsb_release; then
			dist_version="$(lsb_release --codename | cut -f2)"
		fi
		if [ -z "$dist_version" ] && [ -r /etc/lsb-release ]; then
			dist_version="$(. /etc/lsb-release && echo "$DISTRIB_CODENAME")"
		fi
		;;

	debian | raspbian)
		dist_version="$(sed 's/\/.*//' /etc/debian_version | sed 's/\..*//')"
		case "$dist_version" in
		11)
			dist_version="bullseye"
			;;
		10)
			dist_version="buster"
			;;
		9)
			dist_version="stretch"
			;;
		8)
			dist_version="jessie"
			;;
		esac
		;;

	centos | rhel | sles)
		if [ -z "$dist_version" ] && [ -r /etc/os-release ]; then
			dist_version="$(. /etc/os-release && echo "$VERSION_ID")"
		fi
		;;

	*)
		if command_exists lsb_release; then
			dist_version="$(lsb_release --release | cut -f2)"
		fi
		if [ -z "$dist_version" ] && [ -r /etc/os-release ]; then
			dist_version="$(. /etc/os-release && echo "$VERSION_ID")"
		fi
		;;

	esac

	# Check if this is a forked Linux distro
	check_forked

	# Print deprecation warnings for distro versions that recently reached EOL,
	# but may still be commonly used (especially LTS versions).
	case "$lsb_dist.$dist_version" in
	debian.stretch | debian.jessie)
		deprecation_notice "$lsb_dist" "$dist_version"
		;;
	raspbian.stretch | raspbian.jessie)
		deprecation_notice "$lsb_dist" "$dist_version"
		;;
	ubuntu.xenial | ubuntu.trusty)
		deprecation_notice "$lsb_dist" "$dist_version"
		;;
	fedora.*)
		if [ "$dist_version" -lt 33 ]; then
			deprecation_notice "$lsb_dist" "$dist_version"
		fi
		;;
	esac

	# Run setup for each distro accordingly
	case "$lsb_dist" in
	ubuntu | debian | raspbian)
		pre_reqs="apt-transport-https ca-certificates curl"
		if ! command -v gpg >/dev/null; then
			pre_reqs="$pre_reqs gnupg"
		fi
		apt_repo="deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] $DOWNLOAD_URL/linux/$lsb_dist $dist_version $CHANNEL"
		(
			if ! is_dry_run; then
				set -x
			fi
			$sh_c 'apt-get update -qq >/dev/null'
			$sh_c "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $pre_reqs >/dev/null"
			$sh_c 'mkdir -p /etc/apt/keyrings && chmod -R 0755 /etc/apt/keyrings'
			$sh_c "curl -fsSL \"$DOWNLOAD_URL/linux/$lsb_dist/gpg\" | gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg"
			$sh_c "chmod a+r /etc/apt/keyrings/docker.gpg"
			$sh_c "echo \"$apt_repo\" > /etc/apt/sources.list.d/docker.list"
			$sh_c 'apt-get update -qq >/dev/null'
		)
		pkg_version=""
		if [ -n "$VERSION" ]; then
			if is_dry_run; then
				echo "# WARNING: VERSION pinning is not supported in DRY_RUN"
			else
				# Will work for incomplete versions IE (17.12), but may not actually grab the "latest" if in the test channel
				pkg_pattern="$(echo "$VERSION" | sed "s/-ce-/~ce~.*/g" | sed "s/-/.*/g").*-0~$lsb_dist"
				search_command="apt-cache madison 'docker-ce' | grep '$pkg_pattern' | head -1 | awk '{\$1=\$1};1' | cut -d' ' -f 3"
				pkg_version="$($sh_c "$search_command")"
				echo "INFO: Searching repository for VERSION '$VERSION'"
				echo "INFO: $search_command"
				if [ -z "$pkg_version" ]; then
					echo
					echo "ERROR: '$VERSION' not found amongst apt-cache madison results"
					echo
					#						exit 1
					VERSION=""
				fi
				if version_gte "18.09"; then
					search_command="apt-cache madison 'docker-ce-cli' | grep '$pkg_pattern' | head -1 | awk '{\$1=\$1};1' | cut -d' ' -f 3"
					echo "INFO: $search_command"
					cli_pkg_version="=$($sh_c "$search_command")"
				fi
				pkg_version="=$pkg_version"
			fi
		fi
		(
			pkgs="docker-ce${pkg_version%=}"
			if version_gte "18.09"; then
				# older versions didn't ship the cli and containerd as separate packages
				pkgs="$pkgs docker-ce-cli${cli_pkg_version%=} containerd.io"
			fi
			if version_gte "20.10"; then
				pkgs="$pkgs docker-compose-plugin"
			fi
			# TODO(thaJeztah) remove the $CHANNEL check once 22.06 and docker-buildx-plugin is published to the "stable" channel
			if ! is_dry_run; then
				set -x
			fi
			pkgs="$pkgs docker-compose"
			$sh_c "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends $pkgs >/dev/null"
			if version_gte "20.10"; then
				# Install docker-ce-rootless-extras without "--no-install-recommends", so as to install slirp4netns when available
				$sh_c "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker-ce-rootless-extras${pkg_version%=} >/dev/null"
			fi
		)
		echo_docker_as_nonroot
		#			exit 0
		;;
	centos | fedora | rhel)
		if [ "$(uname -m)" != "s390x" ] && [ "$lsb_dist" = "rhel" ]; then
			echo "Packages for RHEL are currently only available for s390x."
			exit 1
		fi
		yum_repo="$DOWNLOAD_URL/linux/$lsb_dist/$REPO_FILE"
		if ! curl -Ifs "$yum_repo" >/dev/null; then
			echo "Error: Unable to curl repository file $yum_repo, is it valid?"
			exit 1
		fi
		if [ "$lsb_dist" = "fedora" ]; then
			pkg_manager="dnf"
			config_manager="dnf config-manager"
			enable_channel_flag="--set-enabled"
			disable_channel_flag="--set-disabled"
			pre_reqs="dnf-plugins-core"
			pkg_suffix="fc$dist_version"
		else
			pkg_manager="yum"
			config_manager="yum-config-manager"
			enable_channel_flag="--enable"
			disable_channel_flag="--disable"
			pre_reqs="yum-utils"
			pkg_suffix="el"
		fi
		(
			if ! is_dry_run; then
				set -x
			fi
			$sh_c "$pkg_manager install -y -q $pre_reqs"
			$sh_c "$config_manager --add-repo $yum_repo"

			if [ "$CHANNEL" != "stable" ]; then
				$sh_c "$config_manager $disable_channel_flag docker-ce-*"
				$sh_c "$config_manager $enable_channel_flag docker-ce-$CHANNEL"
			fi
			$sh_c "$pkg_manager makecache"
		)
		pkg_version=""
		if [ -n "$VERSION" ]; then
			if is_dry_run; then
				echo "# WARNING: VERSION pinning is not supported in DRY_RUN"
			else
				pkg_pattern="$(echo "$VERSION" | sed "s/-ce-/\\\\.ce.*/g" | sed "s/-/.*/g").*$pkg_suffix"
				search_command="$pkg_manager list --showduplicates 'docker-ce' | grep '$pkg_pattern' | tail -1 | awk '{print \$2}'"
				pkg_version="$($sh_c "$search_command")"
				echo "INFO: Searching repository for VERSION '$VERSION'"
				echo "INFO: $search_command"
				if [ -z "$pkg_version" ]; then
					echo
					echo "ERROR: '$VERSION' not found amongst $pkg_manager list results"
					echo
					exit 1
				fi
				if version_gte "18.09"; then
					# older versions don't support a cli package
					search_command="$pkg_manager list --showduplicates 'docker-ce-cli' | grep '$pkg_pattern' | tail -1 | awk '{print \$2}'"
					cli_pkg_version="$($sh_c "$search_command" | cut -d':' -f 2)"
				fi
				# Cut out the epoch and prefix with a '-'
				pkg_version="-$(echo "$pkg_version" | cut -d':' -f 2)"
			fi
		fi
		(
			pkgs="docker-ce$pkg_version"
			if version_gte "18.09"; then
				# older versions didn't ship the cli and containerd as separate packages
				if [ -n "$cli_pkg_version" ]; then
					pkgs="$pkgs docker-ce-cli-$cli_pkg_version containerd.io"
				else
					pkgs="$pkgs docker-ce-cli containerd.io"
				fi
			fi
			if version_gte "20.10"; then
				pkgs="$pkgs docker-compose-plugin docker-ce-rootless-extras$pkg_version"
			fi
			# TODO(thaJeztah) remove the $CHANNEL check once 22.06 and docker-buildx-plugin is published to the "stable" channel
			if ! is_dry_run; then
				set -x
			fi
			pkgs="$pkgs docker-compose"
			$sh_c "$pkg_manager install -y -q $pkgs"
		)
		echo_docker_as_nonroot
		#			exit 0
		;;
	sles)
		if [ "$(uname -m)" != "s390x" ]; then
			echo "Packages for SLES are currently only available for s390x"
			exit 1
		fi

		sles_version="${dist_version##*.}"
		sles_repo="$DOWNLOAD_URL/linux/$lsb_dist/$REPO_FILE"
		opensuse_repo="https://download.opensuse.org/repositories/security:SELinux/SLE_15_SP$sles_version/security:SELinux.repo"
		if ! curl -Ifs "$sles_repo" >/dev/null; then
			echo "Error: Unable to curl repository file $sles_repo, is it valid?"
			exit 1
		fi
		pre_reqs="ca-certificates curl libseccomp2 awk"
		(
			if ! is_dry_run; then
				set -x
			fi
			$sh_c "zypper install -y $pre_reqs"
			$sh_c "zypper addrepo $sles_repo"
			if ! is_dry_run; then
				cat >&2 <<-'EOF'
					WARNING!!
					openSUSE repository (https://download.opensuse.org/repositories/security:SELinux) will be enabled now.
					Do you wish to continue?
					You may press Ctrl+C now to abort this script.
				EOF
				(
					set -x
					sleep 30
				)
			fi
			$sh_c "zypper addrepo $opensuse_repo"
			$sh_c "zypper --gpg-auto-import-keys refresh"
			$sh_c "zypper lr -d"
		)
		pkg_version=""
		if [ -n "$VERSION" ]; then
			if is_dry_run; then
				echo "# WARNING: VERSION pinning is not supported in DRY_RUN"
			else
				pkg_pattern="$(echo "$VERSION" | sed "s/-ce-/\\\\.ce.*/g" | sed "s/-/.*/g")"
				search_command="zypper search -s --match-exact 'docker-ce' | grep '$pkg_pattern' | tail -1 | awk '{print \$6}'"
				pkg_version="$($sh_c "$search_command")"
				echo "INFO: Searching repository for VERSION '$VERSION'"
				echo "INFO: $search_command"
				if [ -z "$pkg_version" ]; then
					echo
					echo "ERROR: '$VERSION' not found amongst zypper list results"
					echo
					exit 1
				fi
				search_command="zypper search -s --match-exact 'docker-ce-cli' | grep '$pkg_pattern' | tail -1 | awk '{print \$6}'"
				# It's okay for cli_pkg_version to be blank, since older versions don't support a cli package
				cli_pkg_version="$($sh_c "$search_command")"
				pkg_version="-$pkg_version"

				search_command="zypper search -s --match-exact 'docker-ce-rootless-extras' | grep '$pkg_pattern' | tail -1 | awk '{print \$6}'"
				rootless_pkg_version="$($sh_c "$search_command")"
				rootless_pkg_version="-$rootless_pkg_version"
			fi
		fi
		(
			pkgs="docker-ce$pkg_version"
			if version_gte "18.09"; then
				if [ -n "$cli_pkg_version" ]; then
					# older versions didn't ship the cli and containerd as separate packages
					pkgs="$pkgs docker-ce-cli-$cli_pkg_version containerd.io"
				else
					pkgs="$pkgs docker-ce-cli containerd.io"
				fi
			fi
			if version_gte "20.10"; then
				pkgs="$pkgs docker-compose-plugin docker-ce-rootless-extras$pkg_version"
			fi
			# TODO(thaJeztah) remove the $CHANNEL check once 22.06 and docker-buildx-plugin is published to the "stable" channel
			if ! is_dry_run; then
				set -x
			fi
			pkgs="$pkgs docker-compose"
			$sh_c "zypper -q install -y $pkgs"
		)
		echo_docker_as_nonroot
		#			exit 0
		;;
	*)
		if [ -z "$lsb_dist" ]; then
			if is_darwin; then
				echo
				echo "ERROR: Unsupported operating system 'macOS'"
				echo "Please get Docker Desktop from https://www.docker.com/products/docker-desktop"
				echo
				exit 1
			fi
		fi
		echo
		echo "ERROR: Unsupported distribution '$lsb_dist'"
		echo
		exit 1
		;;
	esac
	#	exit 1
}

# wrapped up in a function so that we have some protection against only getting
# half the file during "curl | sh"
check_environment
if command_exists docker && [ x"$DRY_RUN" != x"1" ]; then
	remove_docker
fi
do_install
start_docker
check_user
install_mavis

echo "           _____                    _____                    _____                    _____                    _____ "
echo "          /\    \                  /\    \                  /\    \                  /\    \                  /\    \ "
echo "         /::\____\                /::\    \                /::\____\                /::\    \                /::\    \ "
echo "        /::::|   |               /::::\    \              /:::/    /                \:::\    \              /::::\    \ "
echo "       /:::::|   |              /::::::\    \            /:::/    /                  \:::\    \            /::::::\    \ "
echo "      /::::::|   |             /:::/\:::\    \          /:::/    /                    \:::\    \          /:::/\:::\    \ "
echo "     /:::/|::|   |            /:::/__\:::\    \        /:::/____/                      \:::\    \        /:::/__\:::\    \ "
echo "    /:::/ |::|   |           /::::\   \:::\    \       |::|    |                       /::::\    \       \:::\   \:::\    \ "
echo "   /:::/  |::|___|______    /::::::\   \:::\    \      |::|    |     _____    ____    /::::::\    \    ___\:::\   \:::\    \ "
echo "  /:::/   |::::::::\    \  /:::/\:::\   \:::\    \     |::|    |    /\    \  /\   \  /:::/\:::\    \  /\   \:::\   \:::\    \ "
echo " /:::/    |:::::::::\____\/:::/  \:::\   \:::\____\    |::|    |   /::\____\/::\   \/:::/  \:::\____\/::\   \:::\   \:::\____\ "
echo " \::/    / ~~~~~/:::/    /\::/    \:::\  /:::/    /    |::|    |  /:::/    /\:::\  /:::/    \::/    /\:::\   \:::\   \::/    / "
echo "  \/____/      /:::/    /  \/____/ \:::\/:::/    /     |::|    | /:::/    /  \:::\/:::/    / \/____/  \:::\   \:::\   \/____/ "
echo "              /:::/    /            \::::::/    /      |::|____|/:::/    /    \::::::/    /            \:::\   \:::\    \ "
echo "             /:::/    /              \::::/    /       |:::::::::::/    /      \::::/____/              \:::\   \:::\____\ "
echo "            /:::/    /               /:::/    /        \::::::::::/____/        \:::\    \               \:::\  /:::/    / "
echo "           /:::/    /               /:::/    /          ~~~~~~~~~~               \:::\    \               \:::\/:::/    / "
echo "          /:::/    /               /:::/    /                                     \:::\    \               \::::::/    / "
echo "         /:::/    /               /:::/    /                                       \:::\____\               \::::/    / "
echo "         \::/    /                \::/    /                                         \::/    /                \::/    / "
echo "          \/____/                  \/____/                                           \/____/                  \/____/ "
echo -e "---------   ${COLOR_GREEN}Install mavis keeper success , please check it${COLOR_REST}"
echo -e "---------   ${COLOR_GREEN}Run command: sudo journalctl CONTAINER_NAME=keeper -f${COLOR_REST}"
echo -e "---------   ${COLOR_GREEN}Your MAVIS_URL is [http://${MAVIS_URL}]${COLOR_REST}"
echo -e "---------   ${COLOR_GREEN}Your default account and passwd is [admin/admin]${COLOR_REST}"
