-- name: CreateChirp :one
INSERT INTO chirps (body, user_id)
VALUES (
    $1,
    $2
)
RETURNING id, created_at, updated_at, body, user_id;

-- name: GetChirps :many
SELECT id, created_at, updated_at, body, user_id
FROM chirps
ORDER BY created_at ASC;

-- name: GetSingleChirp :one
SELECT * FROM chirps
WHERE id = $1;

-- name: DeleteSingleChirp :one
DELETE FROM chirps
WHERE id = $1 AND user_id = $2
RETURNING id;

-- name: GetChirpsAuthor :many
SELECT id, created_at, updated_at, body, user_id
FROM chirps
WHERE user_id = $1
ORDER BY created_at ASC;