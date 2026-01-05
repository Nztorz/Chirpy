-- name: DeleteAllUsers :exec
-- DEV ONLY: deletes all user rows without touching schema
DELETE FROM users;