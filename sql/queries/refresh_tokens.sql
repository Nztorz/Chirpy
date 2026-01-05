-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens(token, user_id, expires_at, revoked_at)
VALUES (
    $1,
    $2,
    $3,
    $4
)
RETURNING *;

-- name: RefreshTokenExists :one
SELECT user_id
FROM refresh_tokens
WHERE token = $1
AND expires_at > NOW()
AND revoked_at IS NULL;

-- name: RevokeToken :exec
UPDATE refresh_tokens
SET revoked_at = NOW()
WHERE token = $1;