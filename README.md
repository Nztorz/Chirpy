# Chirpy

- Chirpy is a RESTful API written in Golang for posting short messages called chirps, JWT-based


## Features
- User signup, account creation
- User authentication
- User validation
- CRUD operations for chirps
- PostgreSQL with sqlc and goose

## Getting Starter

### Prerequisites
- Go 1.25+
- PostgreSQL
- sqlc
- goose

### Endpoints
## POST 
    - /admin/reset: delete all users in the database

    - /api/users: create a new user with default value of chirp red false. It receives as parameters a JSON with password string, and email string

    - /api/chirps: create a new chirp authenticating, validating and autherizing user. It only accept the body string JSON of the chirp validating the JWT in headers

    - /api/login: validate and authenticate user to start creating new chirps. It accepts a body JSON password string, email. The JWT token has a duration time of 1 hour by default.

    - /api/refresh: check for a JWT and create a refresh token. No body request is needed.

    - /api/revoke: remove the refresh token of a specific user using ID. No body request is needed, the ID of the user is obtained using header token

    - /api/polka/webhooks: receive an authAPI from a third-party service in header. And body JSON with string type of event "user.upgraded" and user id. Will upgrade the user id role to chirp red.

## GET
    - /api/healthz: tells the status of server

    - /admin/metrics: count the number of times a person enters the web/calls the server

    - /api/chirps: It receives an optional author_id as query. It returns all the chirps with the specific user id when query is provided or all the chirps when no query is given

    - /api/chirps/{chirpID}: receives an ID as parameter and respond with only the chirp asked, otherwise 404

## PUT
    - /api/users: update the users data using JWT to obtain the user id. As JSON body requires password string and email string. Respond with the updated safe data user

## DELTE
    - /api/chirps/{chirpID}: delete specified chirp using ID parameter. Respond 204.