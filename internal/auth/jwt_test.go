package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWT(t *testing.T) {

	type jwtPayload struct {
		userID      string
		tokenSecret string
		expiresIn   time.Duration
	}

	tests := []struct {
		name    string
		payload *jwtPayload
		wantErr bool
	}{
		{
			name: "valid jwt",
			payload: &jwtPayload{
				userID:      "8b54a2d5-8773-4513-8b4f-1c36800883e6",
				tokenSecret: "5dc1ce5be7382fa8",
				expiresIn:   60 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "invalid jwt",
			payload: &jwtPayload{
				userID:      "29bd1574-0615-4a9b-8e1d-0f31517e2e71",
				tokenSecret: "0a5f4526b1a06a71",
				expiresIn:   -1 * time.Second,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		// Both test require have a valid uuid userID
		userID, err := uuid.Parse(tt.payload.userID)
		require.NoError(t, err)

		tokenString, err := MakeJWT(userID, tt.payload.tokenSecret, tt.payload.expiresIn)
		require.NoError(t, err)

		if tt.wantErr {
			_, err := ValidateJWT(tokenString, tt.payload.tokenSecret)
			require.Error(t, err)

			return
		}

		userUUID, err := ValidateJWT(tokenString, tt.payload.tokenSecret)

		require.NoError(t, err)
		assert.Equal(t, userUUID, userID)

	}
}
