-- +goose up
-- +goose StatementBegin
ALTER TABLE users 
ADD COLUMN hashed_password TEXT NOT NULL DEFAULT 'unset';

-- +goose StatementEnd

-- +goose down
-- +goose StatementBegin
ALTER TABLE users DROP COLUMN hashed_password; 
-- +goose StatementEnd