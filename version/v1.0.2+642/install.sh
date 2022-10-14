#!/bin/sh
set -e
# Docker CE for Linux installation script
# SCRIPT_COMMIT_SHA="b2e29ef7a9a89840d2333637f7d1900a83e7153f"

MAVIS_STATIC_PAGE=https://pnetwork.github.io/release.mavis
MAVIS_VERSION=v1.0.2+642
TAG=v1.0.2-642
#MAVIS_REPO=
VERSION="20.10"
CHANNEL="stable"
DOWNLOAD_URL="https://download.docker.com"
REPO_FILE="docker-ce.repo"
COLOR_REST='\e[0m'
COLOR_GREEN='\e[0;32m'
COLOR_RED='\e[0;31m'
INSTALL_DIR=${INSTALL_DIR:-/opt/mavis}
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
	if [ "$avail_disk" -lt 39000000 ]; then
		echo -e "${COLOR_RED}Storage size error. Minimum storage size: 40GB${COLOR_REST}"
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
		echo -e "${COLOR_RED}CPU cores error. Minimum CPU cores: 4${COLOR_REST}"
		exit 1
	else
		echo -e "${COLOR_GREEN}check cpu ok${COLOR_REST}"
	fi
	## Check memory
	local avail_mem="$(free -g | grep Mem | awk '{print $2}')"
	if [ "$avail_mem" -lt 15 ]; then
		echo -e "${COLOR_RED}Memory size error. Minimum memory size 16GB${COLOR_REST}"
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
		exit 1
		;;
	*)
		echo -e "The network is down or very slow"
		echo -e "${COLOR_RED}check network status failed${COLOR_REST}"
		exit 1
		;;
	esac
}

keeper_cli() {
	result=$(${sh_c} "docker run --rm -v  ${INSTALL_DIR}:${INSTALL_DIR} -v /var/run/docker.sock:/var/run/docker.sock -e CURRENT_VERSION=${MAVIS_VERSION} -e INSTALL_DIR=${INSTALL_DIR} gcr.io/pentium-mavis/keeper:${TAG} ${1} ${2} ${3} ")
	if echo "${result}" | grep "Not Found Item"; then
		echo -e "${COLOR_RED} ${2} create failed ${COLOR_REST}"
		exit 1
	elif [ -z "$result" ]; then
		echo -e "${COLOR_RED} ${2} create failed ${COLOR_REST}"
		exit 1
	fi
	echo "${result}"
}

install_mavis() {

	## Remove old container
	local old_list="$(echo $($sh_c "docker ps" | grep gcr.io/pentium-mavis | awk '{print $1}'))"
	echo ${old_list}
	if [ x"$old_list" != x"" ]; then
		$sh_c "docker rm --force ${old_list} || true"
	fi

	## check config dir if exist
	if [ -d "${INSTALL_DIR}/config" ]; then
		echo -e "${COLOR_GREEN}Path ${INSTALL_DIR}/config is already exist${COLOR_REST}"
		local first_install=false
		$sh_c "/bin/cp -r  ${INSTALL_DIR}/config ${INSTALL_DIR}/backups/config-$(date +'%Y-%m-%d-%H-%M:')"
		$sh_c "rm -rf ${INSTALL_DIR}/config/*"
	fi

	# Generate Directory Structure
	for i in ${DIR_LIST}; do
		$sh_c "mkdir -p ${INSTALL_DIR}/$i"
	done
	$sh_c "touch ${INSTALL_DIR}/config/current_version ${INSTALL_DIR}/config/old_version ${INSTALL_DIR}/config/${MAVIS_VERSION}"
	$sh_c "echo ${MAVIS_VERSION} > ${INSTALL_DIR}/config/current_version"
	$sh_c "chown -R ${user}:${user} ${INSTALL_DIR}"
        $sh_c "chown -R 1000:1000 ${INSTALL_DIR}/data/ssh-proxy"
        $sh_c "chown -R 1000:1000 ${INSTALL_DIR}/data/rdp-proxy"

	curl ${MAVIS_STATIC_PAGE}/version/${MAVIS_VERSION}/.env -o ${INSTALL_DIR}/config/${MAVIS_VERSION}/.env
	curl ${MAVIS_STATIC_PAGE}/version/${MAVIS_VERSION}/docker-compose.yml -o ${INSTALL_DIR}/config/${MAVIS_VERSION}/docker-compose.yml
	chmod 444 ${INSTALL_DIR}/config/${MAVIS_VERSION}/.env

	if [ x"${first_install}" != x"false" ]; then

		## Get MAVIS_URL
		if [ -z "$MAVIS_URL" ]; then
			local PUBLIC_IP=$(hostname -I | grep -v -E '^(192\.168|10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.)' | awk '{print $1}')
			MAVIS_URL="${PUBLIC_IP}"
			echo
			if [ -z "$PUBLIC_IP" ]; then
				DOMAIN="$(ip route get 1 | awk '{gsub(".*src",""); print $1; exit}')"
				echo DOMAIN="$(ip route get 1 | awk '{gsub(".*src",""); print $1; exit}')" >>${INSTALL_DIR}/config/.env
			else
				DOMAIN="${PUBLIC_IP}"
				echo DOMAIN="${PUBLIC_IP}" >>${INSTALL_DIR}/config/.env
			fi
		else
			DOMAIN=$(echo $MAVIS_URL | sed 's/https\?:\/\///g')
			echo DOMAIN=$(echo $MAVIS_URL | sed 's/https\?:\/\///g') >>${INSTALL_DIR}/config/.env
		fi

		## Generate POSTGRES_PASSWORD
		if [ -z "$POSTGRES_PASSWORD" ]; then
			POSTGRES_PASSWORD=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 13)
		fi

		echo "MAVIS_URL=https://\${DOMAIN}" >>${INSTALL_DIR}/config/.env
        echo "FULL_DOMAIN=\${DOMAIN}" >>${INSTALL_DIR}/config/.env
		echo "MEDIA_STORE_PATH=${MEDIA_STORE_PATH:-\${INSTALL_DIR\}/data/media}" >>${INSTALL_DIR}/config/.env
		echo "SSH_RECORDING_PATH=${SSH_RECORDING_PATH:-\${INSTALL_DIR\}/data/ssh-proxy}" >>${INSTALL_DIR}/config/.env
		echo "RDP_RECORDING_PATH=${RDP_RECORDING_PATH:-\${INSTALL_DIR\}/data/rdp-proxy}" >>${INSTALL_DIR}/config/.env
		echo "\n\n\n### It is not recommended to modify, if you must modify please make sure you know what you are doing ###" >>${INSTALL_DIR}/config/.env
		echo "INSTALL_DIR=${INSTALL_DIR:-/opt/mavis}" >>${INSTALL_DIR}/config/.env
		echo "MASTER_KEYS=${MASTER_KEYS:-$(keeper_cli generate-key MASTER_KEYS)}" >>${INSTALL_DIR}/config/.env
		echo "SECRET_KEY=${SECRET_KEY:-$(keeper_cli generate-key SECRET_KEY)}" >>${INSTALL_DIR}/config/.env
		echo "GATEWAY_CLIENT_ID=${GATEWAY_CLIENT_ID:-$(keeper_cli generate-key GATEWAY_CLIENT_ID)}" >>${INSTALL_DIR}/config/.env
		echo "GATEWAY_CLIENT_SECRET=${GATEWAY_CLIENT_SECRET:-$(keeper_cli generate-key GATEWAY_CLIENT_SECRET)}" >>${INSTALL_DIR}/config/.env
		echo "POSTGRES_HOST=${POSTGRES_HOST:-mavis-postgres}" >>${INSTALL_DIR}/config/.env
		echo "POSTGRES_PORT=${POSTGRES_PORT:-5432}" >>${INSTALL_DIR}/config/.env
		echo "POSTGRES_DB=${POSTGRES_DB:-mavis}" >>${INSTALL_DIR}/config/.env
		echo "POSTGRES_USER=${POSTGRES_USER:-psql}" >>${INSTALL_DIR}/config/.env
		echo "POSTGRES_PASSWORD=${POSTGRES_PASSWORD}" >>${INSTALL_DIR}/config/.env
		echo "DATABASE_URL=${DATABASE_URL:-postgresql://\${POSTGRES_USER\}:\${POSTGRES_PASSWORD\}@\${POSTGRES_HOST\}:\${POSTGRES_PORT\}/\${POSTGRES_DB\}?sslmode=disable}" >>${INSTALL_DIR}/config/.env
		echo "DB_URL=${DB_URL:-postgresql://\${POSTGRES_USER\}:\${POSTGRES_PASSWORD\}@\${POSTGRES_HOST\}:\${POSTGRES_PORT\}/\${POSTGRES_DB\}}" >>${INSTALL_DIR}/config/.env
		echo "REDIS_HOST=${REDIS_HOST:-mavis-redis}" >>${INSTALL_DIR}/config/.env
		echo "REDIS_PORT=${REDIS_PORT:-6379}" >>${INSTALL_DIR}/config/.env
		echo "REDIS_URL=${REDIS_URL:-redis://\${REDIS_HOST\}:\${REDIS_PORT\}/0}" >>${INSTALL_DIR}/config/.env
		echo "CELERY_BROKER_URL=${CELERY_BROKER_URL:-\${REDIS_URL\}}" >>${INSTALL_DIR}/config/.env
		echo "CELERY_RESULT_BACKEND=${CELERY_RESULT_BACKEND:-\${REDIS_URL\}}" >>${INSTALL_DIR}/config/.env
		echo "SSH_PROXY_HOST=${SSH_PROXY_HOST:-\${DOMAIN\}}" >>${INSTALL_DIR}/config/.env
		echo "RDP_PROXY_HOST=${RDP_PROXY_HOST:-\${DOMAIN\}}" >>${INSTALL_DIR}/config/.env

		while read line; do
			v=$(echo "${line}" | cut -d '=' -f 1)
			if /usr/bin/env | grep "${v}" >/dev/null 2>&1 && [ -n "${v}" ] && [ -z $(cat ${INSTALL_DIR}/config/.env | grep "${v}=") ]; then
				/usr/bin/env | grep "${v}=" >>${INSTALL_DIR}/config/.env
			fi
		done <${INSTALL_DIR}/config/${MAVIS_VERSION}/.env

	else
		DOMAIN=$(cat ${INSTALL_DIR}/config/.env | grep "DOMAIN=" | cut -d '=' -f 2)
	fi

	cat >mavis.service <<EOF
[Unit]
Description=Service for mavis
Requires=docker.service
After=docker.service

[Service]
Environment=COMPOSE_HTTP_TIMEOUT=600
ExecStartPre=/bin/sh -c "/usr/bin/docker network create --driver bridge mavis || /bin/true"
ExecStartPre=/bin/sh -c "/usr/bin/docker rm keeper --force || /bin/true"
ExecStartPre=/bin/sh -c "/usr/bin/docker pull gcr.io/pentium-mavis/keeper:\$(cat ${INSTALL_DIR}/config/current_version|sed 's/+/-/g')"
ExecStart=/bin/sh -c "/usr/bin/docker run --rm --log-driver=journald --name=keeper --net=mavis -v /var/run/docker.sock:/var/run/docker.sock -v ${INSTALL_DIR}:${INSTALL_DIR}  -e CURRENT_VERSION=\$(cat ${INSTALL_DIR}/config/current_version) -e INSTALL_DIR=${INSTALL_DIR} gcr.io/pentium-mavis/keeper:\$(cat ${INSTALL_DIR}/config/current_version|sed 's/+/-/g') start"
ExecStop=/bin/sh -c "/usr/bin/docker run --rm --log-driver=journald --name=terminator --net=mavis -v /var/run/docker.sock:/var/run/docker.sock -v ${INSTALL_DIR}:${INSTALL_DIR} -e CURRENT_VERSION=\$(cat ${INSTALL_DIR}/config/current_version) -e INSTALL_DIR=${INSTALL_DIR} gcr.io/pentium-mavis/keeper:\$(cat ${INSTALL_DIR}/config/current_version|sed 's/+/-/g') stop"
StandardOutput=syslog
Restart=always
Type=simple
SuccessExitStatus=137

[Install]
WantedBy=multi-user.target
EOF

	### Certificate

        if [ -f "./tls.crt" ] && [ -f "./tls.key" ];then
                $sh_c "mkdir -p ${INSTALL_DIR}/config/tls && \
                cp tls.crt ${INSTALL_DIR}/config/tls/ && \
                cp tls.key ${INSTALL_DIR}/config/tls/"

                cat >${INSTALL_DIR}/config/tls/certificates.yaml <<EOF
tls:
  stores:
    default:
      defaultCertificate:
        certFile: /tls/tls.crt
        keyFile: /tls/tls.key
  certificates:
    # first certificate
    - certFile: /tls/tls.crt
      keyFile: /tls/tls.key
      stores:
        - default
EOF
	fi
    







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
		exit 1
		;;
	raspbian.stretch | raspbian.jessie)
		deprecation_notice "$lsb_dist" "$dist_version"
		exit 1
		;;
	ubuntu.xenial | ubuntu.trusty)
		deprecation_notice "$lsb_dist" "$dist_version"
		exit 1
		;;
	centos.6 | centos.8 | centos.9)
		deprecation_notice "$lsb_dist" "$dist_version"
		exit 1
		;;
	fedora.*)
		if [ "$dist_version" -lt 33 ]; then
			deprecation_notice "$lsb_dist" "$dist_version"
			exit 1
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
check_user
start_docker
install_mavis

result=$(keeper_cli status)
i=0
while [ x"$(echo ${result} | grep 'status normal')" = x"" ]; do
        echo "Wait for mavis warm up"
        sleep 30
	i=$((i + 1))
	if [ $i -gt 10 ]; then
		echo -e "${COLOR_RED}Check mavis status timeout${COLOR_REST}"
		echo -e "${COLOR_RED}Please reinstall later or Run command to check conatiner status [ sudo docker ps ]${COLOR_REST}"
		exit 1
	fi
	result=$(keeper_cli status)
done

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
echo -e "---------   ${COLOR_GREEN}Your MAVIS_URL is [https://${DOMAIN}]${COLOR_REST}"
echo -e "---------   ${COLOR_GREEN}Your default account and password is [admin/admin]${COLOR_REST}"
