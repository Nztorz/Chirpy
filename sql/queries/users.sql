-- name: CreateUser :one
INSERT INTO users(email, hashed_password)
VALUES (
    $1,
    $2
)
RETURNING *;

-- name: UserExists :one
SELECT *
FROM users
WHERE email = $1;

-- name: UpdateUserData :exec
UPDATE users
SET hashed_password = $1,
    email = $2
WHERE id = $3;

-- name: UpdateChirpyRed :exec
UPDATE users
SET is_chirpy_red = true
WHERE id = $1;