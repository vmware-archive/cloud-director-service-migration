# cloud-director-service-migration

## Overview
This script helps the customers to migrate their on-prem VCD instances to Cloud Director Service

## Try it out

### Prerequisites

1. The host runs the migrate.sh should have packages installed : curl, jq, scp, ssh, sshpass, zip and md5sum
2. Make sure on-prem VCD FQDN is reachable from public internet
3. Make a note of VCD FQDN name, admin credentials, cell OS credentials and database host OS credentials
   In case of appliance setup, cell OS credentials refer to primary cell.
4. Make a note of VCD setup model (appliance / non-appliance)
5. Make a note of CSP organization UUID and the generated API/refresh token

### Build & Run

sh scripts/migrate.sh

## Documentation
The migration scripted tool can be run by using  *sh migrate.sh*

The script execution is as follows
1. The customer has to provide the on-prem VCD site FQDN name (e.g: migration.eng.vmware.com) as scripted tool requests by
    1. Enter on-prem VCD site FQDN name: <host-name>.<domain.name>
2. The scripted tool seeks the administrator username and password of the on-prem VCD site by
    1. Enter admin username for on-prem VCD site <hostname>.<domainname>: <adminUserName>
    2. Enter admin password for on-prem VCD site <hostname>.<domainname>: <adminPassword>
    3. Upon successful collection, scripted tool outputs "Successfully collected <adminUserName> credentials for <hostname>.<domainname>"
3. Migration scripted tool seeks the on-prem VCD instance deployment model as in appliance/non-appliance. Customer has to enter true if it is appliance based or false if it is non-appliance based
    1. Is <hostname>.<domainname> Appliance based [true for Appliance, false for Non-Appliance]: <true/false>
4. Scripted tool finds the active cell (primary cell in case of appliance) and outputs
    1. Found active Cell: <activeCell> (Non-Appliance model)
    2. Found primary Cell: <activeCell> (Appliance model)
5. Customer can cross verify the cell details, scripted tool seeks active cell (primary cell in case of appliance) login os credentials
    1. Enter username for cell <activeCell>: <cellHostUserName>
    2. Enter password for cell <activeCell>: <cellHostPassword>
    3. Upon successful collection, scripted tool outputs "Successfully collected <cellHostUserName> credentials for <activeCell>"
6. Scripted tool makes a copy of /opt/vmware/vcloud-director/etc/responses.properties  and outputs "Successfully downloaded responses.properties from <activeCell>"
    1. Scripted tool finds the database details and outputs "Found Database HOSTNAME: <databaseHost> and "Found Database Name: <databaseName>"
7. If appliance mode, database resides in primary cell. Scripted tool will reuse the primary cell login os credentials. If non-appliance model, scripted tool seeks database host login os credentials
    1. Enter username for database host <databaseHost>: <dbHostUserName>
    2. Enter password for database host <databaseHost>: <dbHostPassword>
8. Scripted tool seeks the CSP org ID and CSP org API token
    1. Enter CSP ORG ID:  <cspOrgId>
    2. Enter CSP ORG refresh token: " <cspOrgRefreshToken>
9. Scripted tool gets the list of environments associated, if it is more than one, it lists all the available environments and customer has to select the required environment
    1. Found following 5 environments in org: <cspOrgId>
        US West - Oregon (xxxxx)
        Australia - Sydney (xxxxx)
        Europe - Germany (xxxxx)
        Asia - Japan (xxxxx)
        Select environment for CDI migration: values (1-4)] : 1
        Scripted tool outputs "Selected Environment: US West - Oregon (xxxxx)
10. Scripted tool invokes the compatibleCheck API
    1. If compatible, scripted tool outputs "Compatibility Check Succeeded, found upgrade category: <upgradeCategory>"
    2. If not compatible, scripted tool exits by printing the API response and "Compatibility check has been failed, check the API response.
11. Scripted tool, takes data only dump from the database and stores as vcloud_db_data.dump
    1. Creates resources.zip by compressing responses.properties (Collected in step 6) and vcloud_db_data.dump (Collected in step 11)
    2. Scripted tool outputs "Successfully collected all required resources from <hostname>.<domainname> for migration"
12. Scripted tool seeks the CDI name to migrate by
    1. Enter CDI Name to migrate: <cdiName>
13. Scripted tool uploads the resources to CDS environment by invoking uploadResources API
    1. Upon successful upload, scripted tool outputs "Upload Resource Task URN: <uploadTaskUrn>"
    2. If upload failed, scripted tool exits by printing API response and "Upload failed, check the API response"
14. Scripted tool setups the maintenance mode in all the cells by running /opt/vmware/vcloud-director/bin/cell-management-tool cell -m true -u <adminUserName> -p '<adminPassword>'
15. Scripted tool invokes the migrate API
    1. Upon successful task initialisation, scripted tool outputs "Migrate to CDI Task ID: <migrateTaskUrn>
    2. Upon failure, scripted tool exits by printing API response and "Migration failed, check the API response
16. Scripted tool check the task status by every minute interval and outputs the migration status until the task status is either "SUCCESS" of "FAILURE"
    1. If SUCCESS, scripted tool succeeds by output "Migrate to CDI status SUCCESS for task <migrateTaskUrn>"
    2. If FAILURE, scripted tool exits by output "Migrate to CDI status FAILURE for task <migrateTaskUrn>"

## Contributing

The cloud-director-service-migration project team welcomes contributions from the community. Before you start working with cloud-director-service-migration, please
read our [Developer Certificate of Origin](https://cla.vmware.com/dco). All contributions to this repository must be
signed as described on that page. Your signature certifies that you wrote the patch or have the right to pass it on
as an open-source patch. For more detailed information, refer to [CONTRIBUTING.md](CONTRIBUTING.md).

## License
Refer [LICENSE](LICENSE)
