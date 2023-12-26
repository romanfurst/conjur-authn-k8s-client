#!/usr/bin/env bash

if [ "$PLATFORM" = 'kubernetes' ]; then
    cli=kubectl
elif [ "$PLATFORM" = 'openshift' ]; then
    cli=oc
fi

init_bash_lib() {
  git submodule update --init --recursive
  bash_lib="$(dirname "${BASH_SOURCE[0]}")/bash-lib"
  . "${bash_lib}/init"
}

check_env_var() {
  if [[ -z "${!1+x}" ]]; then
# where ${var+x} is a parameter expansion which evaluates to nothing if var is unset, and substitutes the string x otherwise.
# https://stackoverflow.com/questions/3601515/how-to-check-if-a-variable-is-set-in-bash/13864829#13864829
    echo "You must set $1 before running these scripts."
    exit 1
  fi
}

announce() {
  echo "++++++++++++++++++++++++++++++++++++++"
  echo ""
  echo "$@"
  echo ""
  echo "++++++++++++++++++++++++++++++++++++++"
}

platform_image_for_pull() {
  local image="$1"
  local namespace="$2"
  if [[ ${PLATFORM} = "openshift" ]]; then
    echo "${PULL_DOCKER_REGISTRY_PATH}/$namespace/$1:$namespace"
  elif [[ "$USE_DOCKER_LOCAL_REGISTRY" = "true" ]]; then
    echo "${PULL_DOCKER_REGISTRY_URL}/$1:$CONJUR_NAMESPACE_NAME"
  else
    echo "${PULL_DOCKER_REGISTRY_PATH}/$1:$CONJUR_NAMESPACE_NAME"
  fi
}

platform_image_for_push() {
  local image="$1"
  local namespace="$2"
  if [[ ${PLATFORM} = "openshift" ]]; then
    echo "${DOCKER_REGISTRY_PATH}/$namespace/$1:$namespace"
  elif [[ "$USE_DOCKER_LOCAL_REGISTRY" = "true" ]]; then
    echo "${DOCKER_REGISTRY_URL}/$1:$CONJUR_NAMESPACE_NAME"
  else
    echo "${DOCKER_REGISTRY_PATH}/$1:$CONJUR_NAMESPACE_NAME"
  fi
}

has_namespace() {
  if "$cli" get namespace  "$1" &>/dev/null; then
    true
  else
    false
  fi
}

has_resource() {
  local selector="$1"
  local num_matching_resources=$("$cli" get pods -n "$CONJUR_NAMESPACE_NAME" --selector "$selector" --no-headers 2>/dev/null | wc -l)
  if [ $num_matching_resources -gt 0 ]; then
    return 0
  else
    return 1
  fi
}

get_pod_name() {
  local pod_identifier="$1"

  # Query to get the pod name, ignoring temp "deploy" pods
  pod_name=$("$cli" get pods | grep "$pod_identifier" | grep -v "deploy" | awk '{ print $1 }')
  echo "$pod_name"
}

get_pods() {
  "$cli" get pods --selector "$1" --no-headers | awk '{ print $1 }'
}

get_master_pod_name() {
  if [[ "$CONJUR_OSS_HELM_INSTALLED" == "true" ]]; then
    pod_list=$(get_pods "app=conjur-oss")
  else
    pod_list=$(get_pods "app=conjur-node,role=master")
  fi
  echo "$pod_list" | awk '{print $1}'
}

get_conjur_cli_pod_name() {
  pod_list="$($cli get pods -n $CONJUR_NAMESPACE_NAME --selector app=conjur-cli --no-headers | awk '{ print $1 }')"
  echo "$pod_list" | awk '{print $1}'
}

run_conjur_cmd_as_admin() {
  local command="$(cat $@)"

  conjur logout > /dev/null
  conjur login -i admin -p "$CONJUR_ADMIN_PASSWORD" > /dev/null

  local output=$(eval "$command")

  conjur logout > /dev/null
  echo "$output"
}

conjur_service_account() {
  if [[ "$CONJUR_OSS_HELM_INSTALLED" == "true" ]]; then
    echo "conjur-oss"
  else
    echo "conjur-cluster"
  fi
}

set_namespace() {
  if [[ $# != 1 ]]; then
    printf "Error in %s/%s - expecting 1 arg.\n" "$(pwd)" "$0"
    exit -1
  fi

  "$cli" config set-context "$($cli config current-context)" --namespace="$1" > /dev/null
}

load_policy() {
  local POLICY_FILE=$1

  run_conjur_cmd_as_admin <<CMD
conjur policy load -b root -f "policy/$POLICY_FILE"
CMD
}

rotate_host_api_key() {
  local host=$1

  run_conjur_cmd_as_admin <<CMD
conjur host rotate-api-key --id "$host"
CMD
}

function wait_for_it() {
  local timeout=$1
  local spacer=2
  shift

  if ! [ $timeout = '-1' ]; then
    local times_to_run=$((timeout / spacer))

    echo "Waiting for '$@' up to $timeout s"
    for i in $(seq $times_to_run); do
      eval $@ > /dev/null && echo 'Success!' && return 0
      echo -n .
      sleep $spacer
    done

    # Last run evaluated. If this fails we return an error exit code to caller
    eval $@
  else
    echo "Waiting for '$@' forever"

    while ! eval $@ > /dev/null; do
      echo -n .
      sleep $spacer
    done
    echo 'Success!'
  fi
}

function external_ip() {
  local service="$1"

  echo "$($cli get svc $service -o jsonpath='{.status.loadBalancer.ingress[0].ip}')"
}

function deployment_status() {
  local deployment=$1

  echo "$($cli describe deploymentconfig $deployment | awk '/^\tStatus:/' |
    awk '{ print $2 }')"
}

function pods_ready() {
  local app_label="$1"

  "$cli" describe pod --selector "app=$app_label" | awk '/Ready/{if ($2 != "True") exit 1}'
}

function urlencode() {
  # urlencode <string>

  # Run as a subshell so that we can indiscriminately set LC_COLLATE
  (
    LC_COLLATE=C

    local length="${#1}"
    for (( i = 0; i < length; i++ )); do
      local c="${1:i:1}"
      case $c in
        [a-zA-Z0-9.~_-]) printf "$c" ;;
        *) printf '%%%02X' "'$c" ;;
      esac
    done
  )
}

function get_ns_pod_names(){
  namespace="${1}"
  "${cli}" -n "${namespace}" get pods -o json \
    |jq -r '.items[].metadata.name'
}

function get_pod_container_names(){
  namespace="${1}"
  pod="${2}"
  "${cli}" -n "${namespace}" get "pod/${pod}" -o json \
    |jq -r '.spec.containers[].name'
}

function check_for_crd() {
  local num_matching_resources=$("$cli" get crd --no-headers 2>/dev/null | grep configurations.secretless.io | wc -l)
  if [ $num_matching_resources -gt 0 ]; then
    "$cli" delete crd configurations.secretless.io
    sleep 10
  fi
}

function clean_web_hooks() {
  announce "clean_web_hooks"
  while true ; do

    local num_matching_resources=$("$cli" get mutatingwebhookconfigurations | grep sidecar-injector.conjur | wc -l)

    if [ $num_matching_resources -gt 0 ]; then
      echo "delete the webhook"
      kubectl delete mutatingwebhookconfigurations $("$cli" get mutatingwebhookconfigurations | grep sidecar-injector.conjur | awk '{ print $1 }' | head -1)
      sleep 1
    else
    echo 'done'
    break
    fi
  done
}



function dump_local_docker_logs(){
  docker ps -a --format '{{.ID}}' |while read cid; do
    container_name="$(docker inspect "${cid}" --format '{{.Name}}' | sed 's+^/++')"
    echo -e "\n\n ======= Jenkins Agent Docker Container Logs: ${container_name} / ${cid} ======="
    docker logs "${cid}"
    echo -e " ======= End of Jenkins Agent Docker Container Logs: ${container_name} / ${cid} ======="
  done
}

function dump_pod_logs(){
  namespace="${1}"
  get_ns_pod_names "${namespace}" | while read -r podname; do
    get_pod_container_names "${namespace}" "${podname}" | while read -r container_name; do
      echo -e "\n\n ======= Container Logs Namespace:${namespace} Pod:${podname} Container:${container_name} ======="
      "${cli}" -n "${namespace}" logs "${podname}" --container "${container_name}" || true
      echo -e " ======= End of Container Logs Namespace:${namespace} Pod:${podname} Container:${container_name} ======="
    done
  done
}

function dump_kubernetes_resources() {
  namespace="$1"
  announce "Kubernetes Resources (${namespace})"
  echo "Status of pods in namespace $namespace:"
  "$cli" get -n "$namespace" pods
  echo "Display pods in namespace $namespace:"
  "$cli" get -n "$namespace" pods -o yaml
  echo "Describe pods in namespace $namespace:"
  "$cli" describe -n "$namespace" pods
  dump_pod_logs "${namespace}"
  echo "Services:in namespace $namespace:"
  "$cli" get -n "$namespace" svc
  echo "ServiceAccounts:in namespace $namespace:"
  "$cli" get -n "$namespace" serviceaccounts
  echo "Deployments in namespace $namespace:"
  "$cli" get -n "$namespace" deployments
  if [[ "$PLATFORM" == "openshift" ]]; then
    echo "DeploymentConfigs in namespace $namespace:"
    "$cli" get -n "$namespace" deploymentconfigs
  fi
  echo "Roles in namespace $namespace:"
  "$cli" get -n "$namespace" roles
  echo "RoleBindings in namespace $namespace:"
  "$cli" get -n "$namespace" rolebindings
  echo "ClusterRoles in the cluster:"
  "$cli" get clusterroles
  echo "ClusterRoleBindings in the cluster:"
  "$cli" get clusterrolebindings
}

function dump_conjur_namespace_upon_error {
  if [ $? -ne 0 ]; then
    announce "Test FAILED!!!! Displaying resources in Conjur Namespace"
    dump_kubernetes_resources "$CONJUR_NAMESPACE_NAME"
    dump_local_docker_logs
  fi
}

function dump_application_namespace_upon_error {
  if [ $? -ne 0 ]; then
    announce "Test FAILED!!!! Displaying Kubernetes Resources"
    dump_kubernetes_resources "$TEST_APP_NAMESPACE_NAME"
    dump_kubernetes_resources "$CONJUR_NAMESPACE_NAME"
    dump_local_docker_logs
  fi
}

function dump_authentication_policy {
  announce "Authentication policy:"
  cat "policy/generated/$TEST_APP_NAMESPACE_NAME.project-authn.yml"
}

function get_admin_password {
    echo "$(kubectl exec \
                --namespace "$CONJUR_NAMESPACE_NAME" \
                deploy/conjur-oss \
                --container conjur-oss \
                -- conjurctl role retrieve-key "$CONJUR_ACCOUNT":user:admin | tail -1)"
}

function split_on_comma_delimiter {
  # given a comma-delimited string, return a bash array of the string's parts
  # "summon-sidecar,secretless-broker" -> (summon-sidecar secretless-broker)
  IFS=',' read -r -a array <<< "$1"; unset IFS
  echo "${array[@]}"
}

function uninstall_helm_release {
  release_name="$1"
  namespace="$2"

  if [ "$(helm list -q -n "$namespace" | grep "^$release_name$")" = "$release_name" ]; then
    helm uninstall "$release_name" -n "$namespace"
  fi
}

function run_command_with_platform {

  GCLOUD_INCLUDES="-i"
  if [[ "$CONJUR_PLATFORM" == "gke" || "$APP_PLATFORM" == "gke" ]]; then
    if [[ ! -z "${GCLOUD_SERVICE_KEY}" ]]; then
      GCLOUD_INCLUDES="-v$GCLOUD_SERVICE_KEY:/tmp$GCLOUD_SERVICE_KEY"
    fi
  else
    GCLOUD_CLUSTER_NAME="gke"
    GCLOUD_ZONE="gke"
    GCLOUD_PROJECT_NAME="gke"
  fi

  docker run --rm \
    -i \
    -e CONJUR_OSS_HELM_INSTALLED \
    -e PLATFORM \
    -e UNIQUE_TEST_ID \
    -e CONJUR_PLATFORM \
    -e APP_PLATFORM \
    -e INSTALL_APPS \
    -e USE_DOCKER_LOCAL_REGISTRY \
    -e DOCKER_REGISTRY_URL \
    -e DOCKER_REGISTRY_PATH \
    -e PULL_DOCKER_REGISTRY_URL \
    -e PULL_DOCKER_REGISTRY_PATH \
    -e CONJUR_ACCOUNT \
    -e CONJUR_ADMIN_PASSWORD \
    -e CONJUR_APPLIANCE_URL \
    -e CONJUR_AUTHN_LOGIN_PREFIX \
    -e AUTHENTICATOR_ID \
    -e CONJUR_NAMESPACE_NAME \
    -e SAMPLE_APP_BACKEND_DB_PASSWORD \
    -e TEST_APP_DATABASE \
    -e TEST_APP_NAMESPACE_NAME \
    -e TEST_APP_NAMESPACE_LABEL \
    -e CONJUR_APPLIANCE_IMAGE \
    -e CONJUR_FOLLOWER_URL \
    -e DEPLOY_MASTER_CLUSTER \
    -e HELM_RELEASE \
    -e GCLOUD_CLUSTER_NAME \
    -e GCLOUD_ZONE \
    -e GCLOUD_PROJECT_NAME \
    -e OPENSHIFT_VERSION \
    -e OPENSHIFT_URL \
    -e OPENSHIFT_USERNAME \
    -e OPENSHIFT_PASSWORD \
    -e OSHIFT_CONJUR_ADMIN_USERNAME \
    -e OSHIFT_CLUSTER_ADMIN_USERNAME \
    -e CONJUR_LOG_LEVEL \
    -e TEST_APP_TAG \
    -e TEST_APP_REPO \
    -e TEST_APP_LOADBALANCER_SVCS \
    -e SECRETS_PROVIDER_TAG \
    -e SECRETLESS_BROKER_TAG \
    -e GCLOUD_SERVICE_KEY=/tmp"$GCLOUD_SERVICE_KEY" \
    "$GCLOUD_INCLUDES" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v ~/.config:/root/.config \
    -v "$PWD/../..":/src \
    -w /src/bin/test-workflow \
    "$PLATFORM_CONTAINER:$CONJUR_NAMESPACE_NAME" \
    bash -c "
      ./platform_login.sh
      $*
    "
}
