# HORUSEC_SCRIPTS

##### Warning! All scripts must be generated from the root of the horusec project

## Update tag version on git
Exemple:
```text
./deployments/scripts/up-version.sh release
``` 

This script aims to update the version of github.
Using <a href="https://github.com/wiliansilvazup/semver-cli">SEMVER_CLI</a> we will update the version that is currently running on the project.

- Right after we performed some validations that are:
     - Check if semver is installed <a href="deployments/scripts/up-version.sh">deployments/scripts/install-semver.sh</a>
     - Check if the passed parameters are valid

### Parameters
|  Name       | Position | Required |   Description                            |
|-------------|----------|----------|------------------------------------------|
| UPDATE_TYPE | 1        |  true    | The type of update must be: for the `develop` branch the available types are: `alpha, rc`; for the `master` branch the available types are: `minor, major, release` |

After he updates the version of the `.semver.yaml` file he will commit with a standard message. And if the branch is a master it will download the correction to the branch automatically.

## Update tool version on dockerhub
Exemple:
```text
./deployments/scripts/update-image-tool.sh bandit alpha false
``` 

* <a href="deployments/scripts/update-image-tool.sh">deployments/scripts/update-image-tool.sh</a> 

The purpose of this script is to automate the update process in the dockerhub, of the analysis tools used in horusec-cli.
Using <a href="https://github.com/wiliansilvazup/semver-cli">SEMVER_CLI</a> we will update the version that is running the selected tool.

- Right after we performed some validations that are:
     - Check if semver is installed <a href="deployments/up-version.sh">deployments/install-semver.sh</a>
     - Check if the passed parameters are valid

### Parameters
|  Name       | Position | Required |   Description                            |
|-------------|----------|----------|------------------------------------------|
| TOOL_NAME           | 1        |  true    | The name of tool to update must be: `bandit, brakeman, gitleaks, gosec, npmaudit, safety, securitycodescan, spotbugs, hcl, horusec-kotlin, horusec-java, horusec-leaks` to get dockerfile and path correctly to update |
| UPDATE_TYPE         | 2        |  true    | The type of update must be: `alpha, rc, minor, major, release`  to get path correctly to update .semver.yaml file |
| IS_TO_UPDATE_LATEST | 3        |  true    | The is to update latest must be: `true, false` to check if is to update latest version |


## Update horusec service version on dockerhub
Exemple:
```text
./deployments/scripts/update-image-service.sh release
``` 
* <a href="deployments/scripts/update-image-service.sh">deployments/scripts/update-image-service.sh</a> 

The purpose of this script is to automate the update process in the dockerhub, of services used in this project.
Using <a href="https://github.com/wiliansilvazup/semver-cli">SEMVER_CLI</a> we will update the running version of the selected service.

- Right after we performed some validations that are:
     - Check if semver is installed <a href="deployments/up-version.sh">deployments/install-semver.sh</a>
     - Check if the passed parameters are valid

### Parameters
|  Name       | Position | Required |   Description                            |
|-------------|----------|----------|------------------------------------------|
| SERVICE_NAME        | 1        |  true    | The name of tool to update must be: `horusec-messages, horusec-manager, horusec-api, horusec-analytic, horusec-account` to get dockerfile and path correctly to update |
| UPDATE_TYPE         | 2        |  true    | The type of update must be: `alpha, rc, minor, major, release`  to get path correctly to update .semver.yaml file |
| IS_TO_UPDATE_LATEST | 3        |  true    | The is to update latest must be: `true, false` to check if is to update latest version |

## Create new migration in database
Exemple:
```text
./deployments/scripts/migration-create.sh new_migration
``` 
* <a href="deployments/scripts/migration-create.sh">deployments/scripts/migration-create.sh</a>
 
This script will automate the process of creating a new migration and before running it will verify that your migration CLI is installed successfully, using the <a href="deployments/scripts/migration-install.sh">deployments/scripts/migration-install.sh</a> script
When you are installing, administrative permission is required to move the migrate binary to `/usr/local/bin` folder.

### Parameters
|  Name        | Position | Required |   Description                            |
|--------------|----------|----------|------------------------------------------|
| MIGRATION_FILE_NAME | 1        |  true   | Will create new migration with this name |

## Run migration in database
Exemple:
```text
./deployments/scripts/migration-run.sh up
./deployments/scripts/migration-run.sh up 1
./deployments/scripts/migration-run.sh down 1
./deployments/scripts/migration-run.sh drop
./deployments/scripts/migration-run.sh goto 20200820095000
./deployments/scripts/migration-run.sh version
``` 
* <a href="deployments/scripts/migration-run.sh">deployments/scripts/migration-run.sh</a>
 
This script will automate the process of run a migration and before running it will verify that your migration CLI is installed successfully, using the <a href="deployments/scripts/migration-install.sh">deployments/scripts/migration-install.sh</a> script
When you are installing, administrative permission is required to move the migrate binary to `/usr/local/bin` folder.
If you want change connection you can change directly in file. We use To connect in database by default:
POSTGRES_USER="root"
POSTGRES_PASSWORD="root"
POSTGRES_HOST="localhost"
POSTGRES_PORT="5432"
POSTGRES_DB_NAME="horusecDB"
POSTGRES_SSL_MODE="disable"

To run migration you can use o param MIGRATE_TYPE, as it will check if you want to use the types:

| MIGRATE_TYPE | MIGRATE_NUMBERS | DESCRIPTION |
|--------------|-----------------|-------------|
|goto          | Version   | Migrate to version V |
|up            | [N]       | Apply all or N up migrations |
|down          | [N]       | Apply all or N down migrations |
|drop          |           | Drop everything inside database |
|force         | Version   | Set version V but don't run migration (ignores dirty state) |
|version       |           | Print current migration version |

### Parameters
|  Name           | Position | Required |   Description                                    |
|-----------------|----------|----------|--------------------------------------------------|
| MIGRATE_TYPE    | 1        | false    | Type of migration to execute. By default is `up` |
| MIGRATE_NUMBERS | 2        | false    | Type of number to execute before migrate type    |

## Update Horusec-CLI
Exemple:
```text
./horusec-cli/deployments/scripts/update-image.sh release
``` 
* <a href="horusec-cli/deployments/scripts/update-image.sh">horusec-cli/deployments/scripts/update-image.sh</a> 

The purpose of this script is to automate the process of generating horusec-cli binaries to all necessary operation system.
Using <a href="https://github.com/wiliansilvazup/semver-cli">SEMVER_CLI</a> we will update the running version of the selected service.

- Right after we performed some validations that are:
     - Check if semver is installed <a href="deployments/up-version.sh">deployments/install-semver.sh</a>
     - Check if the passed parameters are valid
     - Check if you send update_type `minor or major or release` we need reset alpha and rc

Before generate scripts you can see in path `horusec-cli/bin/horusec` will show the new version generated and all binaries for you to add them to your versioning repository.
If you pass the param `SEND_NEW_VERSION_TO_S3` equals `true` it will send the new binaries to s3.
If you pass the param `IS_TO_UPDATE_LATEST` equals `true` it will update latest version file `horusec-cli/deployments/version-cli-latest.txt` and send the file to s3.
And before it will update the file `horusec-cli/deployments/all-version-cli.txt` with the new version and send the file to s3

**WARN!!! All files sent to `s3 bucket` need change to public access to download of files**

### Parameters
|  Name                  | Position | Required |   Description                            |
|------------------------|----------|----------|------------------------------------------|
| UPDATE_TYPE            | 1        |  true    | The type of update must be: `alpha, rc, minor, major, release`  to get path correctly to update .semver.yaml file |
| SEND_NEW_VERSION_TO_S3 | 2        |  false   | If this params is equals `true` we go update version in s3 |
| IS_TO_UPDATE_LATEST    | 3        |  false   | If this params is equals `true` we go update latest version and send to s3 |

## Install latest version Horusec-CLI
Exemple:
```text
./horusec-cli/deployments/scripts/install.sh
``` 
* <a href="horusec-cli/deployments/scripts/install.sh">horusec-cli/deployments/scripts/install.sh</a> 

This is the script used in pipelines and in the documentation to acquire the latest stable version of horusec from the project's `bucket s3` and move the binary to the proper installation location!
Attention! This script is only available for linux and mac. On Windows platform you will have to download and run horusec manually.
When you are installing, administrative permission is required to move the horusec binary to `/usr/local/bin` folder.

### Parameters
|  Name        | Position | Required |   Description                            |
|--------------|----------|----------|------------------------------------------|
| URL_DOWNLOAD | 1        |  false   | download binary horusec from this url |
