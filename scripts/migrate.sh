#------------------------------------------------------------------------------
#  Copyright (c) 2022 VMware, Inc. All rights reserved.
#------------------------------------------------------------------------------

#!/bin/bash
set -o pipefail

readonly CONSOLE_URL='console.cloud.vmware.com'
readonly OPERATOR_URL='vcdc-operator-prod-us-west-2.vdp.vmware.com'
readonly RESPONSES_PROPERTIES_FILE_NAME=responses.properties
readonly DATA_ONLY_DUMP_FILE_NAME=vcloud_db_data.dump
readonly UPLOAD_FILE_NAME=resources.zip
readonly INPUT_PROPS='/tmp/migration.properties'

function log_msg () {
    echo $(date '+%b %d %T') ${0##*/}: "$@" | tee -a /tmp/migrate_to_cdi.log
}

function print_error () {
    if [ ${1} -ne 0 ]; then
        shift
        log_msg ERROR: $@
    fi
}

function die () {
    if [ ${1} -ne 0 ]; then
        presistInputValues
        shift
        log_msg ERROR: $@
        exit 1
    fi
}

function presistInputValues() {
    if [[ -f $INPUT_PROPS ]]; then
       mv $INPUT_PROPS $INPUT_PROPS.old
    fi

    if [[ ! -z "$SITE_NAME" ]]; then
       echo SITE_NAME=$SITE_NAME >> $INPUT_PROPS
    fi

    if [[ ! -z "$SITE_ADMIN_USERNAME" ]]; then
       echo SITE_ADMIN_USERNAME=$SITE_ADMIN_USERNAME >> $INPUT_PROPS
    fi

    if [[ ! -z "$IS_APPLIANCE" ]]; then
       echo IS_APPLIANCE=$IS_APPLIANCE >> $INPUT_PROPS
    fi

    if [[ ! -z "$CSP_ORG_ID" ]]; then
       echo CSP_ORG_ID=$CSP_ORG_ID >> $INPUT_PROPS
    fi

    if [[ ! -z "$CSP_ORG_REFRESH_TOKEN" ]]; then
       echo CSP_ORG_REFRESH_TOKEN=$CSP_ORG_REFRESH_TOKEN >> $INPUT_PROPS
    fi

    if [[ ! -z "$CELL_USERNAME" ]]; then
       echo CELL_USERNAME=$CELL_USERNAME >> $INPUT_PROPS
    fi

    if [[ ! -z "$DBHOST_USERNAME" ]]; then
       echo DBHOST_USERNAME=$DBHOST_USERNAME >> $INPUT_PROPS
    fi
}

function validateFlagReuse() {
    reuse=$(echo $@ | tr '[:upper:]' '[:lower:]')
    if ! [[ $reuse == y || $reuse == n ]]; then
        die 1 "unrecognized value for reusage, expecting [y/n], found $reuse"
    fi
}

function getSupportedApiVersion() {
    local siteName=${1}
    curl --insecure -H 'Accept: application/*+json' -s "https://$siteName/api/versions" | jq -r '.versionInfo | last' | jq -r .version
}

function getCloudCells() {
    local apiVersion=${1}
    local siteName=${2}
    local siteAdminUserName=${3}
    local siteAdminPassword=${4}

    local jwtAccessToken=$(curl -is -k -H "Accept:application/*+json;version=$apiVersion" \
        -u "$siteAdminUserName@System:$siteAdminPassword" \
        -X POST  "https://$siteName/api/sessions" \
        | grep X-VMWARE-VCLOUD-ACCESS-TOKEN | awk '{print $2}'  |  tr -d [:space:])

    if [ -z "$jwtAccessToken" ]; then
        die 1 "Unable to establish the session with $siteName"
    fi

    local jwtAuthHeader="Authorization: Bearer $jwtAccessToken"

    curl -s "https://$siteName/cloudapi/1.0.0/cells" -k \
        -H "$jwtAuthHeader" \
        -H "Accept: application/json;version=$apiVersion" | jq -r '.values[] | select(.isActive==true)' | jq -r .name
}

function downloadResponsesProperties() {
    log_msg INFO: In ${FUNCNAME[0]}
    local primaryCell=${1}
    local cellUserName=${2}
    local cellUserPassword=${3}
    local downloadLocation=${4}
    log_msg DEBUG: Downloading $RESPONSES_PROPERTIES_FILE_NAME from $primaryCell
    sshpass -p ${cellUserPassword} scp -o StrictHostKeyChecking=no ${cellUserName}@${primaryCell}:/opt/vmware/vcloud-director/etc/$RESPONSES_PROPERTIES_FILE_NAME $downloadLocation/$RESPONSES_PROPERTIES_FILE_NAME
    local -i download_status=$?
    if [ $download_status -ne 0 ]; then
        die $download_status "Exit status $donwload_status while copying $RESPONSES_PROPERTIES_FILE_NAME from $primaryCell"
    fi
    log_msg DEBUG: Successfully downloaded $RESPONSES_PROPERTIES_FILE_NAME from $primaryCell
}

function getDatabaseHostName() {
    local databaseHost=${1}
    local isAppliance=${2}
    local databaseUrl=${3}
    if [ "$isAppliance" = false ] ; then
        databaseHost=$(echo $databaseUrl | cut -d'/' -f3 | cut -d':' -f1)
    fi
    echo $databaseHost
}

function getDatabaseName() {
    local databaseUrl=${1}
    local databaseName=$(echo $databaseUrl | cut -d'/' -f4 | cut -d'?' -f1)
    echo $databaseName
}

function generateDataOnlyDumpDB() {
    local databaseHost=${1}
    local databaseName=${2}
    local dbHostUserName=${3}
    local dbHostPassword=${4}
    local isAppliance=${5}
    local downloadLocation=${6}
    log_msg DEBUG: Dumping data-only on $databaseName database from $databaseHost
    if [ "$isAppliance" = false ]; then
        sshpass -p ${dbHostPassword} ssh -o StrictHostKeyChecking=no ${dbHostUserName}@${databaseHost} "pg_dump -a -h ${databaseHost} -d $databaseName -U postgres -Fc  -f /tmp/$DATA_ONLY_DUMP_FILE_NAME"
        local -i dump_status=$?
        if [ $dump_status -ne 0 ]; then
            die $dump_status "[Non-Appliance] Exit status $dump_status while dumping data-only on $databaseName database on $databaseHost"
        fi
        log_msg DEBUG: Successfully dumped data-only on $databaseName database from $databaseHost
    else
        sshpass -p ${dbHostPassword} ssh -o StrictHostKeyChecking=no ${dbHostUserName}@${databaseHost} "su - postgres -c \"pg_dump -a -Fc $databaseName -f /tmp/$DATA_ONLY_DUMP_FILE_NAME\""
        local -i dump_status=$?
        if [ $dump_status -ne 0 ]; then
            die $dump_status "[Appliance] Exit status $dump_status while dumping data-only on $databaseName database on $databaseHost"
        fi
        log_msg DEBUG: Successfully dumped data-only on $databaseName database on $databaseHost
    fi
    sshpass -p ${dbHostPassword} scp -o StrictHostKeyChecking=no ${dbHostUserName}@${databaseHost}:/tmp/$DATA_ONLY_DUMP_FILE_NAME  $downloadLocation/$DATA_ONLY_DUMP_FILE_NAME
    local -i copy_status=$?
    if [ $copy_status -ne 0 ]; then
        die $copy_status "Exit status $copy_status while copying  data-only database dump on $databaseName database from $databaseHost"
    fi
    log_msg DEBUG: Successfully copied data-only database dump on $databaseName database from $databaseHost
}

function zipResources() {
    local downloadLocation=${1}
    cd $downloadLocation
    zip $UPLOAD_FILE_NAME $DATA_ONLY_DUMP_FILE_NAME $RESPONSES_PROPERTIES_FILE_NAME
    local -i zip_status=$?
    if [ $zip_status -ne 0 ]; then
       die $zip_status "Error occured while zipping the required resources for migration"
    fi
    ls -lrt
    cd -
}

function getSupportedDatabaseSchemaVersions() {
    local primaryCell=${1}
    local cellUserName=${2}
    local cellUserPassword=${3}
    RESULTS=$(sshpass -p ${cellUserPassword} ssh -o StrictHostKeyChecking=no ${cellUserName}@${primaryCell} "/opt/vmware/vcloud-director/bin/cell-management-tool manage-config -l -n database.schema.version")
    echo $RESULTS | grep -Eo "\[.*\]"
}

function preCheck() {
    which curl
    local -i curl_install_status=$?
    if [ $curl_install_status -ne 0 ]; then
       die $curl_install_status "curl is not detected for running the script"
    fi

    which jq
    local -i jq_install_status=$?
    if [ $jq_install_status -ne 0 ]; then
       die $jq_install_status "jq is not detected for running the script"
    fi

    which zip
    local -i zip_install_status=$?
    if [ $zip_install_status -ne 0 ]; then
       die $zip_install_status "zip is not detected for running the script"
    fi

    which ssh
    local -i ssh_install_status=$?
    if [ $ssh_install_status -ne 0 ]; then
       die $ssh_install_status "ssh is not detected for running the script"
    fi

    which scp
    local -i scp_install_status=$?
    if [ $scp_install_status -ne 0 ]; then
       die $scp_install_status "scp is not detected for running the script"
    fi

    which sshpass
    local -i sshpass_install_status=$?
    if [ $sshpass_install_status -ne 0 ]; then
       die $sshpass_install_status "ssh is not detected for running the script"
    fi

    which md5sum
    local -i md5sum_install_status=$?
    if [ $md5sum_install_status -ne 0 ]; then
       die $md5sum_install_status "md5sum is not detected for running the script"
    fi
}

function getJwtToken() {
    local refreshToken=${1}
    curl -s -q -X POST "https://$CONSOLE_URL/csp/gateway/am/api/auth/api-tokens/authorize" \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        -d refresh_token="$refreshToken" | jq -r .access_token
}

function getEnvironmentsForOrg() {
    local orgId=${1}
    local refreshToken=${2}
    local token=$(getJwtToken $refreshToken)
    curl -s -X GET "https://${OPERATOR_URL}/organizations/urn:vcdc:organization:${orgId}/environments" \
        -H 'Content-Type: application/json' -H 'Accept: application/json' -H "Authorization: Bearer ${token}"
}

function checkCompatible() {
    local siteName=${1}
    local siteAdminUserName=${2}
    local siteAdminPassword=${3}
    local primaryCell=${4}
    local cellUserName=${5}
    local cellUserPassword=${6}
    local envUrn=${7}
    local refreshToken=${8}
    local token=$(getJwtToken $refreshToken)
    local databaseSchemaVersion=$(getSupportedDatabaseSchemaVersions $primaryCell $cellUserName $cellUserPassword)
    local data="{
           \"sourceParams\": {
               \"vcdHostname\": \"${siteName}\",
               \"vcdPrincipal\": \"${siteAdminUserName}\",
               \"vcdAuthentication\": \"${siteAdminPassword}\",
               \"vcdAuthenticationType\": \"BASIC_AUTH\",
               \"databaseSchemaVersion\": ${databaseSchemaVersion}
           }
       }"
    curl -s -X POST "https://${OPERATOR_URL}/environment/${envUrn}/migration/check-compatibility" \
        -H 'Content-Type: application/json' -H 'Accept: application/json' -H "Authorization: Bearer ${token}" \
        --data-raw "${data}"
}

function uploadResourceToS3() {
    local uploadLocation=${1}
    local envUrn=${2}
    local refreshToken=${3}
    local token=$(getJwtToken $refreshToken)
    local md5CheckSum=$(md5sum $uploadLocation/$UPLOAD_FILE_NAME | awk '{print $1}')
    curl -X POST "https://${OPERATOR_URL}/environment/${envUrn}/migration/upload-resources" \
        -H 'accept: application/json' \
        -H "Authorization: Bearer ${token}" \
        -H 'Content-Type: application/octet-stream' \
        -H "x-md5-checksum: ${md5CheckSum}" \
        -H "Transfer-Encoding: chunked" \
        -T $uploadLocation/$UPLOAD_FILE_NAME \
        --progress-bar | tee response.out
}

function retrieveTrial() {
    local orgId=${1}
    local refreshToken=${2}
    local token=$(getJwtToken $refreshToken)
    curl -s -X GET "https://${OPERATOR_URL}/organizations/urn:vcdc:organization:${orgId}/trials?limit=100" \
        -H 'Content-Type: application/json' -H 'Accept: application/json' -H "Authorization: Bearer ${token}"
}

function retrieveUnclaimedTrial() {
    local orgId=${1}
    local refreshToken=${2}
    local trial=''
    local trialResponse=$(retrieveTrial $orgId $refreshToken)
    local unclaimedTrial=$(echo $trialResponse | jq -r '(last(.values[] | select(.claimed==null) | .))')
    if [[ ! -z "$unclaimedTrial" ]] | [[ "$unclaimedTrial" != "null" ]]; then
        local trialUuid=$(echo $unclaimedTrial | jq -r .id)
        local trialExpiry=$(echo $unclaimedTrial | jq -r .expiry)
        trial="{
            \"id\": \"${trialUuid}\",
            \"expiry\": \"${trialExpiry}\"
       }"
    fi
    echo $trial
}

function migrateToCDS() {
    local siteName=${1}
    local siteAdminUserName=${2}
    local siteAdminPassword=${3}
    local primaryCell=${4}
    local cellUserName=${5}
    local cellUserPassword=${6}
    local upgradeCategory=${7}
    local uploadTaskUuid=${8}
    local cdiName=${9}
    local envUrn=${10}
    local orgId=${11}
    local refreshToken=${12}

    local trial=$(retrieveUnclaimedTrial $orgId $refreshToken)
    local token=$(getJwtToken $refreshToken)
    local databaseSchemaVersion=$(getSupportedDatabaseSchemaVersions $primaryCell $cellUserName $cellUserPassword)
    local data=''
    if [[ -z "$trial" ]]; then
        data="{
            \"name\": \"${cdiName}\",
            \"upgradeCategory\": \"${upgradeCategory}\",
            \"migrationType\" : \"ONPREM-TO-CDS\",
            \"uploadResourcesId\": \"${uploadTaskUuid}\",
            \"sourceParams\": {
                \"vcdHostname\" : \"${siteName}\",
                \"vcdPrincipal\": \"${siteAdminUserName}\",
                \"vcdAuthentication\": \"${siteAdminPassword}\",
                \"vcdAuthenticationType\": \"BASIC_AUTH\",
                \"databaseSchemaVersion\": ${databaseSchemaVersion}
            }
        }"
    else
        data="{
            \"name\": \"${cdiName}\",
            \"upgradeCategory\": \"${upgradeCategory}\",
            \"migrationType\" : \"ONPREM-TO-CDS\",
            \"uploadResourcesId\": \"${uploadTaskUuid}\",
            \"sourceParams\": {
                \"vcdHostname\" : \"${siteName}\",
                \"vcdPrincipal\": \"${siteAdminUserName}\",
                \"vcdAuthentication\": \"${siteAdminPassword}\",
                \"vcdAuthenticationType\": \"BASIC_AUTH\",
                \"databaseSchemaVersion\": ${databaseSchemaVersion}
            },
            \"trial\": ${trial}
        }"
    fi
    curl -s -X POST "https://${OPERATOR_URL}/environment/${envUrn}/migration/migrate" \
        -H 'Content-Type: application/json' -H 'Accept: application/json' -H "Authorization: Bearer ${token}" \
        --data-raw "${data}"
}

function getTaskStatus() {
    local migrateTaskUrn=${1}
    local envUrn=${2}
    local refreshToken=${3}
    local token=$(getJwtToken $refreshToken)
    curl -s -X GET "https://${OPERATOR_URL}/environment/${envUrn}/tasks/${migrateTaskUrn}" \
        -H 'Content-Type: application/json' -H 'Accept: application/json' -H "Authorization: Bearer ${token}"
}

function waitForTask() {
    local runStatus=null
    local migrateTaskUrn=${1}
    local envUrn=${2}
    local refreshToken=${3}
    while [[ $runStatus == null  || $runStatus == "IN_PROGRESS" ]]
    do
        sleep 60
        taskRunStatus=$(getTaskStatus $migrateTaskUrn $envUrn $refreshToken)
        runStatus=$(echo $taskRunStatus | jq -r .status)
        runMessage=$(echo $taskRunStatus | jq -r .message)
        log_msg INFO: "Migrate to CDI task run status: $runStatus - $runMessage"
    done
}

function main () {
    preCheck
    unset SITE_NAME SITE_ADMIN_USERNAME SITE_ADMIN_PASSWORD
    unset IS_APPLIANCE DBHOST_USERNAME DBHOST_USERPASSWORD CELL_USERNAME CELL_USERPASSWORD
    unset CSP_ORG_ID CSP_ORG_REFRESH_TOKEN

    if [[ -f $INPUT_PROPS ]]; then
        read -p "Migration Input properties file present, wish to reuse [y/n]: " reuse
        validateFlagReuse $reuse

       if [[ $reuse == y || $reuse == Y ]]; then
           log_msg DEBUG: "Script will reuse the input values located in $INPUT_PROPS"
           source $INPUT_PROPS
       else
           log_msg DEBUG: "Script will prompt the input values"
       fi
    fi

    if [[ ! -z "$SITE_NAME" ]]; then
        read -p "Site FQDN name (found: $SITE_NAME), wish to reuse [y/n]: " reuse
        validateFlagReuse $reuse
    else
        reuse=n
    fi
    if [[ $reuse == n || $reuse == N ]]; then
        read -p "Enter site FQDN name: " SITE_NAME
    fi

    if [[ ! -z "$SITE_ADMIN_USERNAME" ]]; then
        read -p "Site admin user name (found: $SITE_ADMIN_USERNAME), wish to reuse [y/n]: " reuse
        validateFlagReuse $reuse
    else
        reuse=n
    fi
    if [[ $reuse == n || $reuse == N ]]; then
        read -p "Enter admin username for site $SITE_NAME: " SITE_ADMIN_USERNAME
    fi

    if [[ -z "$SITE_ADMIN_PASSWORD" ]]; then
        read -p "Enter admin password for site $SITE_NAME: " -s SITE_ADMIN_PASSWORD
    fi
    log_msg INFO: "Successfully collected $SITE_ADMIN_USERNAME credentials for $SITE_NAME"

    if [[ ! -z "$IS_APPLIANCE" ]]; then
        read -p "Is $SITE_NAME appliance based (found: $IS_APPLIANCE), wish to reuse [y/n]: " reuse
        validateFlagReuse $reuse
    else
        reuse=n
    fi
    if [[ $reuse == n || $reuse == N ]]; then
        read -p "Is $SITE_NAME Appliance based [true for Appliance, false for Non-Appliance]: " IS_APPLIANCE
    fi

    IS_APPLIANCE=$(echo $IS_APPLIANCE | tr '[:upper:]' '[:lower:]')
    if ! [[ $IS_APPLIANCE == true || $IS_APPLIANCE == false ]]
    then
        die 1 "unrecognized value for 'is Appliance Based' $IS_APPLIANCE, expecting [true/false]"
    fi

    local supportedApiVersion=$(getSupportedApiVersion $SITE_NAME)
    if [ -z "$supportedApiVersion" ]; then
        die 1 "Unable to find supported API version in $SITE_NAME"
    fi
    log_msg INFO: "Found Supported API Version: $supportedApiVersion"

    local cloudCells=$(getCloudCells $supportedApiVersion $SITE_NAME $SITE_ADMIN_USERNAME $SITE_ADMIN_PASSWORD)
    if [ -z "$cloudCells" ]; then
        die 1 "Couldn't find any active cells in $SITE_NAME"
    fi
    local primaryCell=""
    if [ "$IS_APPLIANCE" = false ] ; then
       primaryCell=$(echo $cloudCells | cut -d ' ' -f1 | tr '\n' ' ')
    else
       for cell in ${cloudCells}
       do
           local isPrimary=$(curl -s -k https://${cell}:5480/api/1.0.0/isPrimary | jq -r .isPrimary)
           if [ "$isPrimary" = true ]; then
               primaryCell=${cell}
               break
           fi
       done
    fi
    if [ -z "$primaryCell" ]; then
        die 1 "Couldn't find active (primary) cell in $SITE_NAME"
    fi

    if [ "$IS_APPLIANCE" = false ] ; then
        log_msg INFO: "Found active Cell: $primaryCell"
    else
        log_msg INFO: "Found primary Cell: $primaryCell"
    fi

    if [[ ! -z "$CELL_USERNAME" ]]; then
        read -p " Username for cell $primaryCell (found: $CELL_USERNAME), wish to reuse [y/n]: " reuse
        validateFlagReuse $reuse
    else
        reuse=n
    fi
    if [[ $reuse == n || $reuse == N ]]; then
        read -p "Enter username for cell $primaryCell: " CELL_USERNAME
    fi
    if [[ -z "$CELL_USERPASSWORD" ]]; then
        read -p "Enter password for cell $primaryCell: " -s CELL_USERPASSWORD
    fi
    log_msg INFO: "Successfully collected $CELL_USERNAME credentials for $primaryCell"

    local downloadLocation=/tmp/${SITE_NAME}
    mkdir -p ${downloadLocation}
    downloadResponsesProperties $primaryCell $CELL_USERNAME $CELL_USERPASSWORD $downloadLocation
    local databaseUrl=$(grep database.jdbcUrl $downloadLocation/$RESPONSES_PROPERTIES_FILE_NAME | cut -d'=' -f2 | tr -d [:space:])
    local databaseHost=$(getDatabaseHostName $primaryCell $IS_APPLIANCE $databaseUrl)
    log_msg INFO: "Found Database HOSTNAME: $databaseHost"
    local databaseName=$(getDatabaseName $databaseUrl)
    log_msg INFO: "Found Database Name: $databaseName"

    if [ "$IS_APPLIANCE" = false ]; then
        if [[ ! -z "$DBHOST_USERNAME" ]]; then
            read -p "Username for DB Host $databaseHost (found: $DBHOST_USERNAME), wish to reuse [y/n]: " reuse
            validateFlagReuse $reuse
        else
            reuse=n
        fi
        if [[ $reuse == n || $reuse == N ]]; then
            read -p "Enter username for database host $databaseHost: " DBHOST_USERNAME
        fi
        if [[ -z "$DBHOST_USERPASSWORD" ]]; then
           read -p "Enter password for database host $databaseHost: " -s DBHOST_USERPASSWORD
        fi
        log_msg INFO: "Successfully collected $DBHOST_USERNAME credentials for $databaseHost"
    else
        DBHOST_USERNAME=$CELL_USERNAME
        DBHOST_USERPASSWORD=$CELL_USERPASSWORD
    fi

    if [[ ! -z "$CSP_ORG_ID" ]]; then
        read -p "CSP ORG ID (found: $CSP_ORG_ID), wish to reuse [y/n]: " reuse
        validateFlagReuse $reuse
    else
        reuse=n
    fi
    if [[ $reuse == n || $reuse == N ]]; then
        read -p "Enter CSP ORG ID: " CSP_ORG_ID
    fi

    if [[ ! -z "$CSP_ORG_REFRESH_TOKEN" ]]; then
        read -p "CSP ORG refresh Token (found: $CSP_ORG_REFRESH_TOKEN), wish to reuse [y/n]: " reuse
        validateFlagReuse $reuse
    else
        reuse=n
    fi
    if [[ $reuse == n || $reuse == N ]]; then
        read -p "Enter CSP ORG refresh token: "  CSP_ORG_REFRESH_TOKEN
    fi

    local jwtToken=$(getJwtToken $CSP_ORG_REFRESH_TOKEN)
    if [[ -z "$jwtToken" || "$jwtToken" == null ]]; then
        die 1 "Invalid refresh token has been entered"
    fi

    log_msg INFO: "Retrieving list of environments associated for org: $CSP_ORG_ID"
    local envResponse=$(getEnvironmentsForOrg $CSP_ORG_ID $CSP_ORG_REFRESH_TOKEN)
    local envCount=$(echo $envResponse | jq -r '.values | length')
    local envUrn

    if [ $envCount -lt 1 ]
    then
        die 1 "No environments are associated for org: $CSP_ORG_ID"
        exit 1
    fi
    log_msg INFO: "Found following $envCount environments in org: $CSP_ORG_ID"
    echo $envResponse | jq -r .values[].name
    local envUrn=""
    local envName=""
    if [ $envCount -gt 1 ]
    then
        read -p "Select environment for CDI migration: values (1-${envCount})]: " envSelect
        if [[ $envSelect -gt $envCount || $envSelect -lt 1 ]]
        then
            die 1 "Invalid environment selected"
        else
            envSelect=$(expr $envSelect-1)
            envUrn=$(echo $envResponse | jq -r .values[$envSelect].id)
            envName=$(echo $envResponse | jq -r .values[$envSelect].name)
            log_msg INFO: "Selected Environment: ${envName}"
        fi
    else
        envSelect=0
        envUrn=$(echo $envResponse | jq -r .values[$envSelect].id)
        envName=$(echo $envResponse | jq -r .values[$envSelect].name)
        log_msg INFO: "Selected Default Environment: ${envName}"
    fi

    local upgradeCategory=""
    if [[ ! -z "$UPGRADE_CATEGORY" ]]; then
       upgradeCategory="$UPGRADE_CATEGORY"
    else
        local compatiblityResponse=$(checkCompatible $SITE_NAME $SITE_ADMIN_USERNAME $SITE_ADMIN_PASSWORD $primaryCell $CELL_USERNAME $CELL_USERPASSWORD $envUrn $CSP_ORG_REFRESH_TOKEN)
        log_msg DEBUG: "Compatiblity Response: $compatiblityResponse"
        local isCompatible=$(echo $compatiblityResponse | jq -r .build.compatible)
        if [ "$isCompatible" != true ] ; then
            echo $compatiblityResponse | jq .
            die 1 "Compatiblity check has been failed, check the API response"
        fi
        upgradeCategory=$(echo $compatiblityResponse | jq -r .build.cdsBuildCategory)
    fi
    log_msg INFO: "Compatibility Check Succeeded, found upgrade category: $upgradeCategory"

    generateDataOnlyDumpDB $databaseHost $databaseName $DBHOST_USERNAME $DBHOST_USERPASSWORD $IS_APPLIANCE $downloadLocation
    zipResources $downloadLocation
    log_msg INFO: "Successfully collected all required resources from $SITE_NAME for migration"
    presistInputValues
    if [[ -z "$CDI_NAME" ]]; then
        read -p "Enter CDI Name to migrate: " CDI_NAME
    fi

    log_msg INFO: "Uploading collected resources from $SITE_NAME for migration"
    local uploadResponse=$(uploadResourceToS3 $downloadLocation $envUrn $CSP_ORG_REFRESH_TOKEN)
    log_msg DEBUG: "Upload Resource Task Response: $uploadResponse"
    local uploadTaskStatus=$(echo $uploadResponse | jq -r .status)
    if [[ $uploadTaskStatus != "SUCCESS" ]]; then
        echo $uploadResponse | jq .
        die 1 "Upload failed, check the API response"
    fi
    local uploadTaskUrn=$(echo $uploadResponse | jq -r .id)
        if [[ $uploadTaskUrn != "urn:vcdc:task:"* ]]; then
        echo $uploadResponse | jq .
        die 1 "Upload failed, check the API response"
    fi
    log_msg INFO: "Upload Resource Task URN: $uploadTaskUrn"
    local uploadTaskUuid=$(echo $uploadTaskUrn | sed -e "s/urn:vcdc:task://g")
    log_msg INFO: "Upload Resource Task ID: $uploadTaskUuid"

    log_msg INFO: "Setting up maintenance mode on all cloud cells"
    for cell in ${cloudCells}
    do
        log_msg DEBUG: Entering maintenance mode on $cell
        sshpass -p ${CELL_USERPASSWORD} ssh -o StrictHostKeyChecking=no ${CELL_USERNAME}@${cell} "/opt/vmware/vcloud-director/bin/cell-management-tool cell -m true -u ${SITE_ADMIN_USERNAME} -p '${SITE_ADMIN_PASSWORD}'"
        local -i maintenance_status=$?
        if [ $maintenance_status -ne 0 ]; then
           die $maintenance_status "Exit status $maintenance_status while entering maintenance mode on $cell"
        fi
        log_msg DEBUG: Successfully entered maintenance mode on $cell
    done
    log_msg INFO: "Successfully entered maintenance mode on all cloud cells"

    local migrateResponse=$(migrateToCDS $SITE_NAME $SITE_ADMIN_USERNAME $SITE_ADMIN_PASSWORD $primaryCell $CELL_USERNAME $CELL_USERPASSWORD $upgradeCategory $uploadTaskUuid $CDI_NAME $envUrn $CSP_ORG_ID $CSP_ORG_REFRESH_TOKEN)
    log_msg DEBUG: "Migrate to CDI Task Response: $migrateResponse"
    local migrateTaskUrn=$(echo $migrateResponse | jq -r .id)
    if [[ $migrateTaskUrn != "urn:vcdc:task:"* ]]; then
        echo $migrateResponse | jq .
        die 1 "Migration failed, check the API response"
    fi
    log_msg INFO: "Migrate to CDI Task ID: $migrateTaskUrn"

    local instanceUrn=$(echo $migrateResponse | jq -r .entityId)
    local instanceName=$(echo $migrateResponse | jq -r .entityName)
    local orgUrn=$(echo $migrateResponse | jq -r .ownerId)
    local instanceDetails="{ \"instanceName\" : \"$instanceName\", \"environmentName\" : \"$envName\", \"instanceUrn\" : \"$instanceUrn\", \"environmentUrn\" : \"$envUrn\", \"orgnizationUrn\" : \"$orgUrn\" }"
    echo $instanceDetails > instance_details.json

    waitForTask $migrateTaskUrn $envUrn $CSP_ORG_REFRESH_TOKEN
    local taskCompletionResponse=$(getTaskStatus $migrateTaskUrn $envUrn $CSP_ORG_REFRESH_TOKEN)
    local taskCompletionStatus=$(echo $taskCompletionResponse | jq -r .status)
    if [[ $taskCompletionStatus != "SUCCESS" ]]; then
        echo $taskCompletionResponse | jq .
        die 1 "Migration failed, check the task API response"
    fi
    log_msg INFO: "Migrate to CDI status $taskCompletionStatus for task $migrateTaskUrn"
}

main "$@"
