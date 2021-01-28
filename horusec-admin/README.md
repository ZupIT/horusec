# Horusec-admin

The purpose of this service is to maintain the Horusec settings.
The service will update its values in a data centralizer in case we are currently using postgresql and the relevant services will acquire their values through this connection.

**Warning**
This service will generate random hash in your console when start, this hash is necessary to setup on webpage or request into `authorization` header to setup security of project.

# Installing
For install all dependences run into horusec-admin folder this command:
```shell
npm install
```

# Running Application
## Native
For run using `npm` run this command
```
npm start
```

## VsCode
For run using `vscode` we recommend using the following configuration:

`tasks.json`
```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "build",
      "type": "shell",
      "command": "npx tsc"
    }
  ]
}
```

`launch.json`
```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "node",
      "request": "launch",
      "name": "launch program",
      "preLaunchTask": "build",
      "skipFiles": [ "<node_internals>/**"],
      "program": "${workspaceFolder}/dist/app.js"
    }
  ]
}
```

# Running Unit Tests
## Native
For run using `npm` run this command
```
npm run test
```

## VsCode
For run using `vscode` we recommend using the following configuration and run specific file you need debug:
`launch.json`
```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "node",
      "request": "launch",
      "name": "Jest Current File",
      "program": "${workspaceFolder}/node_modules/.bin/jest",
      "args": ["${relativeFile}"],
      "console": "integratedTerminal",
      "internalConsoleOptions": "neverOpen",
      "windows": {
        "program": "${workspaceFolder}/node_modules/jest/bin/jest"
      }
    }
  ]
}
```

# Running coverage
## Native
For run using `npm` run this command
```
npm run coverage
```

# Environments
To change variables environment to run your analysis also you set new values.

| Environment Name                              | Default Value                                                    | Description                                                  |
|-----------------------------------------------|------------------------------------------------------------------|--------------------------------------------------------------|
| HORUSEC_DATABASE_SQL_URI                      | postgresql://root:root@127.0.0.1:5432/horusec_db?sslmode=disable | This environment get uri to connect on database POSTGRES     |
| HORUSEC_DATABASE_SQL_LOG_MODE                 | false                                                            | This environment get bool to enable logs on POSTGRES         |
| HORUSEC_PORT                                  | 3000                                                             | This environment get the port that the service will start    |
