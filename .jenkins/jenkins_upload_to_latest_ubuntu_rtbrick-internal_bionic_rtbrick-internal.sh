#!/usr/bin/env bash

# Fail hard and fast. Exit at the first error or undefined variable.
set -ue;

# Load functions from the jenkins_shell_functions.sh file. This looks for the
# functions file either in the current directory or in the ${__jenkins_scripts_dir}
# or in the ./.jenkins/ sub-directory.
# shellcheck disable=SC1091
__shell_funcs="jenkins_shell_functions.sh";
if [ -f "./$__shell_funcs" ]; then
	# shellcheck source=/dev/null
	. "./$__shell_funcs";
else
	if [ -f "${__jenkins_scripts_dir:-./.jenkins}/$__shell_funcs" ]; then
		# shellcheck source=/dev/null
		. "${__jenkins_scripts_dir:-./.jenkins}/$__shell_funcs";
	fi
fi
jenkins_shell_functions_loaded;

# Since the script will exit at the first error try and print details about the
# command which errored. The trap_debug function is defined in
# jenkins_shell_functions.sh. errtrace is bash specific.
[ "${BASH_VERSION:-0}" != "0" ] && set -o errtrace;
trap 'trap_debug "$?" "$BASH_COMMAND" "$LINENO" "${BASH_SOURCE[0]}"' ERR;

# Print debugging information.
[ "${__global_debug:-0}" -gt "0" ] && {
	echo "DEBUG: environment information:";
	echo "---------------------------------------------------------------";
	env;
	echo "---------------------------------------------------------------";
}
[ "${__global_debug:-0}" -gt "1" ] && {
	set -x;
	# functrace is bash specific.
	[ "${BASH_VERSION:-0}" != "0" ] && set -o functrace;
}

# Dependencies on other programs which might not be installed. If any of these
# are missing the script will exit here with an error. We can also rely on
# values discovered and exporter by jenkins_shell_functions .
_jq="$(which jq) -er --monochrome-output";
_curl="$(which curl) -fsSL";

ME="jenkins_upload_to_latest_ubuntu_rtbrick-internal_bionic_rtbrick-internal.sh";	# Useful for log messages.

REPO_NAME="latest_ubuntu_rtbrick-internal_bionic_rtbrick-internal";
PUBLISH_PATH="latest/ubuntu/rtbrick-internal";
# https://github.com/aptly-dev/aptly/blob/master/api/publish.go#L44
PUBLISH_PATH_ESCAPED="latest_ubuntu_rtbrick-internal";

APTLY_API_URL="https://pkg.rtbrick.net/aptly-api";
APTLY_API_USER="abjibdevak";
APTLY_API_PASS="ciljOncukmerkyoythiripderm4Opam-";

# shellcheck disable=SC2012
_deb="$(ls -t ./*.deb | grep -E -v '^.\/rtbrick.*-(dev|dbg)_' | head -n 1)";

# TODO: Due to the fact that the aptly api returns "200 OK" even in case of
# errors or problems curl will also return exit code 0 (success). In order to
# detect a problem we need to inspect the returned JSON.
logmsg "Trying to upload package ${_deb} to repository $REPO_NAME" "$ME";
$_curl --user "$APTLY_API_USER:$APTLY_API_PASS"			\
	-XPOST -F "file=@${_deb}" "$APTLY_API_URL/files/$REPO_NAME" | $_jq '.';
$_curl --user "$APTLY_API_USER:$APTLY_API_PASS"			\
	-XPOST "$APTLY_API_URL/repos/$REPO_NAME/file/$REPO_NAME/${_deb}" | $_jq '.';

logmsg "Trying to update published repository at $PUBLISH_PATH" "$ME";
$_curl --user "$APTLY_API_USER:$APTLY_API_PASS"			\
	-XPUT -H 'Content-Type: application/json' 		\
	--data "{\"ForceOverwrite\": true}"			\
	"$APTLY_API_URL/publish/filesystem:nginx:$PUBLISH_PATH_ESCAPED/bionic" | $_jq '.';

REPO_NAME="latest_ubuntu_rtbrick-internal-dev_bionic_rtbrick-internal-dev";
PUBLISH_PATH="latest/ubuntu/rtbrick-internal-dev";
# https://github.com/aptly-dev/aptly/blob/master/api/publish.go#L44
PUBLISH_PATH_ESCAPED="latest_ubuntu_rtbrick-internal-dev";

# shellcheck disable=SC2012
_deb="";
_deb="$(ls -t ./*.deb | grep -E '^.\/rtbrick.*-dev_'| head -n 1)" || {
	warmsg "No -dev package found";
};

[ -n "$_deb" ] && {
	logmsg "Trying to upload package ${_deb} to repository $REPO_NAME" "$ME";
	$_curl --user "$APTLY_API_USER:$APTLY_API_PASS"			\
		-XPOST -F "file=@${_deb}" "$APTLY_API_URL/files/$REPO_NAME" | $_jq '.';
	$_curl --user "$APTLY_API_USER:$APTLY_API_PASS"			\
		-XPOST "$APTLY_API_URL/repos/$REPO_NAME/file/$REPO_NAME/${_deb}" | $_jq '.';

	logmsg "Trying to update published repository at $PUBLISH_PATH" "$ME";
	$_curl --user "$APTLY_API_USER:$APTLY_API_PASS"			\
		-XPUT -H 'Content-Type: application/json' 		\
		--data "{\"ForceOverwrite\": true}"			\
		"$APTLY_API_URL/publish/filesystem:nginx:$PUBLISH_PATH_ESCAPED/bionic" | $_jq '.';
}

# shellcheck disable=SC2012
_deb="";
_deb="$(ls -t ./*.deb | grep -E '^.\/rtbrick.*-dbg_'| head -n 1)" || {
	warmsg "No -dbg package found";
};

[ -n "$_deb" ] && {
	logmsg "Trying to upload package ${_deb} to repository $REPO_NAME" "$ME";
	$_curl --user "$APTLY_API_USER:$APTLY_API_PASS"			\
		-XPOST -F "file=@${_deb}" "$APTLY_API_URL/files/$REPO_NAME" | $_jq '.';
	$_curl --user "$APTLY_API_USER:$APTLY_API_PASS"			\
		-XPOST "$APTLY_API_URL/repos/$REPO_NAME/file/$REPO_NAME/${_deb}" | $_jq '.';

	logmsg "Trying to update published repository at $PUBLISH_PATH" "$ME";
	$_curl --user "$APTLY_API_USER:$APTLY_API_PASS"			\
		-XPUT -H 'Content-Type: application/json' 		\
		--data "{\"ForceOverwrite\": true}"			\
		"$APTLY_API_URL/publish/filesystem:nginx:$PUBLISH_PATH_ESCAPED/bionic" | $_jq '.';
}

logmsg "Finished uploading package(s)" "$ME";
