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
% sh migrate.sh
Enter site FQDN name: <hostname>.<domainname>
Enter admin username for site <hostname>.<domainname>: <adminUserName>
Enter admin password for site <hostname>.<domainname>: <adminPassword>
Successfully collected <adminUserName> credentials for <hostname>.<domainname>
Is <hostname>.<domainname> Appliance based [true for Appliance, false for Non-Appliance]: <true/false>
#With the credentials provided, extracts the supported API version
#Found Supported API Version: <supportedApiVersion>
Enter username for cell <primaryCell>: <cellHostUserName>
Enter password for cell <primaryCell>: <cellHostPassword>
Enter username for database host <databaseHost>: <dbHostUserName>
Enter password for database host <databaseHost>: <dbHostPassword>
Enter CSP ORG ID: <cspOrgId>
Enter CSP ORG refresh token: <cspOrgRefreshToken>
#Here it lists the available environment if more than one environment subscribed. Customer can select the desired environment
Select environment for CDI migration: values (1-<envCount>)]: <integerValue>
#checkCompatible API will be called
#If the setup can be migrated: Compatibility Check Succeeded, found upgrade category: <upgradeCategory>
#If the setup cann't be migrated: Compatiblity check has been failed, check the API response
Enter CDI Name to migrate: <cdiName>
#Script collects the data only dump and responses.properties, zips it as resource.zip
#-rw-------  1 wheel  wheel       640 Nov  4 13:02 responses.properties
#-rw-r--r--  1 wheel  wheel  10782262 Nov  4 13:03 vcloud_db_data.dump
#-rw-r--r--  1 wheel  wheel  10343694 Nov  4 13:03 resources.zip
#Successfully collected all required resources from <hostname>.<domainname> for migration
#Invokes the uploadResources API, upon success returns the task ID
#Invokes the migrate API, returns the task ID
#Migrate to CDI Task ID: urn:vcdc:task:<taskUUID>
#Script wait till the migration completes

## Contributing

The cloud-director-service-migration project team welcomes contributions from the community. Before you start working with cloud-director-service-migration, please
read our [Developer Certificate of Origin](https://cla.vmware.com/dco). All contributions to this repository must be
signed as described on that page. Your signature certifies that you wrote the patch or have the right to pass it on
as an open-source patch. For more detailed information, refer to [CONTRIBUTING.md](CONTRIBUTING.md).

## License
Refer [LICENSE] (/LICENSE)
