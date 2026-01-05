package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Nztorz/Chirpy/internal/auth"
	"github.com/Nztorz/Chirpy/internal/database"
	"github.com/Nztorz/Chirpy/utils"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func main() {
	godotenv.Load()
	mux := http.NewServeMux()

	// Get the URL of the database
	dbURL := os.Getenv("DB_URL")
	// what environment is currently working on
	environment := os.Getenv("PLATFORM")
	// OPEN CONECTION WITH DATABASE
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		panic("database conection error")
	}

	// create a new instance of the struct
	apiCfg := apiConfig{}

	dbQueries := database.New(db)

	apiCfg.db = dbQueries
	apiCfg.platform = environment
	// save the file server
	serveIndex := http.StripPrefix("/app", http.FileServer(http.Dir(".")))
	serveImages := http.StripPrefix("/app/assets", http.FileServer(http.Dir("./assets/")))
	// register the middleware at each call on app
	mux.Handle("/app/", apiCfg.middleWareMetricsInc(serveIndex))
	mux.Handle("/app/assets/", apiCfg.middleWareMetricsInc(serveImages))

	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// handler to know how many times the middleware has been called
	mux.HandleFunc("GET /admin/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		htmlResponse := fmt.Sprintf(`<html>
						<body>
							<h1>Welcome, Chirpy Admin</h1>
							<p>Chirpy has been visited %d times!</p>
						</body>
						</html>`, apiCfg.fileserverHits.Load())

		w.Write([]byte(htmlResponse))
	})
	// delete all the users at any time
	mux.HandleFunc("POST /admin/reset", func(w http.ResponseWriter, r *http.Request) {
		if apiCfg.platform != "dev" {
			utils.RespondJSONError(w, 403, "403 Forbidden")
			return
		}

		err := apiCfg.db.DeleteAllUsers(r.Context())
		if err != nil {
			utils.RespondJSONError(w, 500, "something went wrong")
			return
		}

		utils.RespondJSON(w, 200, http.StatusOK)
	})

	// create a new user
	mux.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) {

		type Params struct {
			Password string `json:"password"`
			Email    string `json:"email"`
		}

		type ResponseUser struct {
			ID          uuid.UUID `json:"id"`
			CreatedAt   time.Time `json:"created_at"`
			UpdatedAt   time.Time `json:"updated_at"`
			Email       string    `json:"email"`
			IsChirpyRed bool      `json:"is_chirpy_red"`
		}

		decoder := json.NewDecoder(r.Body)
		params := Params{}
		err := decoder.Decode(&params)
		if err != nil {
			utils.RespondJSONError(w, 500, "something went wrong")
			return
		}

		// hash the password
		hashedPassword, err := auth.HashPassword(params.Password)
		if err != nil {
			utils.RespondJSONError(w, http.StatusInternalServerError, "problems hashing password")
			return
		}

		user, err := apiCfg.db.CreateUser(r.Context(), database.CreateUserParams{
			Email:          params.Email,
			HashedPassword: hashedPassword,
		})

		response := ResponseUser{
			ID:          user.ID,
			CreatedAt:   user.CreatedAt,
			UpdatedAt:   user.UpdatedAt,
			Email:       user.Email,
			IsChirpyRed: user.IsChirpyRed,
		}
		utils.RespondJSON(w, 201, response)
	})

	// chirp validation
	// length and body cleanse
	// create a new chirp
	mux.HandleFunc("POST /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		// check for an active user
		tokenString, err := auth.GetBearerToken(r.Header)
		if err != nil {
			utils.RespondJSONError(w, http.StatusInternalServerError, "error getting token header")
			return
		}

		userUUID, err := auth.ValidateJWT(tokenString, apiCfg.secret)
		if err != nil {
			utils.RespondJSONError(w, 401, "Unauthorized")
			return
		}

		// struct expected of the body
		type RequestBody struct {
			Body string `json:"body"`
		}

		// Response struct
		type ResponseChirp struct {
			ID        uuid.UUID `json:"id"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			Body      string    `json:"body"`
			UserID    uuid.UUID `json:"user_id"`
		}

		// Validations Begin
		decoder := json.NewDecoder(r.Body)
		requestBody := RequestBody{}
		err = decoder.Decode(&requestBody)
		if err != nil || len(requestBody.Body) <= 0 {
			utils.RespondJSONError(w, 500, "Something went wrong")
			return
		}

		// if the chirp is larger than 140 chars
		if len(requestBody.Body) > 140 {
			utils.RespondJSONError(w, 400, "Chirp is too long")
			return
		}

		// replace forbidden words
		re := regexp.MustCompile(`(?i)\b(kerfuffle|sharbet|fornax)\b`)
		requestBody.Body = re.ReplaceAllLiteralString(requestBody.Body, "****")

		// Validation End

		// create chirp
		chirp, err := apiCfg.db.CreateChirp(r.Context(), database.CreateChirpParams{
			Body:   requestBody.Body,
			UserID: userUUID,
		})
		if err != nil {
			utils.RespondJSONError(w, 400, err.Error())
			return
		}

		utils.RespondJSON(w, 201, ResponseChirp{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		})
	})

	// Get All Chirps
	mux.HandleFunc("GET /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		// Response struct
		type ResponseChirp struct {
			ID        uuid.UUID `json:"id"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			Body      string    `json:"body"`
			UserID    uuid.UUID `json:"user_id"`
		}

		s := r.URL.Query().Get("author_id")
		var chirps []database.Chirp

		if s == "" {
			chirps, err = apiCfg.db.GetChirps(r.Context())
			if err != nil {
				utils.RespondJSONError(w, http.StatusInternalServerError, "server error")
				return
			}
		} else {
			// parse user_id
			userID, err := uuid.Parse(s)
			if err != nil {
				utils.RespondJSONError(w, http.StatusInternalServerError, "server error")
				return
			}

			chirps, err = apiCfg.db.GetChirpsAuthor(r.Context(), userID)
		}

		// initialize a new array of response chirp
		var responseChirps []ResponseChirp

		// iterate over the chirps to format the response
		for _, i := range chirps {
			responseChirps = append(responseChirps, ResponseChirp{
				ID:        i.ID,
				CreatedAt: i.CreatedAt,
				UpdatedAt: i.UpdatedAt,
				Body:      i.Body,
				UserID:    i.UserID,
			})
		}

		// respond with 200 status
		utils.RespondJSON(w, 200, responseChirps)
	})

	mux.HandleFunc("GET /api/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) {
		// // Get the JWT token
		// token, err := auth.GetBearerToken(r.Header)
		// log.Println("token")
		// log.Println(token)
		// if err != nil {
		// 	utils.RespondJSONError(w, http.StatusNotFound, "token not found in headers")
		// 	return
		// }

		// // get userID
		// userID, err := auth.ValidateJWT(token, apiCfg.secret)
		// if err != nil {
		// 	utils.RespondJSONError(w, http.StatusBadRequest, "userID not found")
		// 	return
		// }

		// Get ChirpID
		path := r.URL.Path
		parts := strings.Split(path, "/")

		if len(parts) != 4 {
			utils.RespondJSONError(w, http.StatusBadRequest, "no chirpID")
			return
		}

		stringID := parts[3]

		chirpID, err := uuid.Parse(stringID)
		if err != nil {
			utils.RespondJSONError(w, http.StatusInternalServerError, "error parsing chirpID")
			return
		}

		type Response struct {
			ID        uuid.UUID `json:"id"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			Body      string    `json:"body"`
			UserID    uuid.UUID `json:"user_id"`
		}

		// look for the chirp
		chirp, err := apiCfg.db.GetSingleChirp(r.Context(), chirpID)
		if err != nil {
			utils.RespondJSONError(w, http.StatusNotFound, "can't get the chirp")
		}

		utils.RespondJSON(w, 200, Response{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		})

	})

	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		type Payload struct {
			Password         string        `json:"password"`
			Email            string        `json:"email"`
			ExpiresInSeconds time.Duration `json:"-"`
		}

		type ResponseUser struct {
			ID           uuid.UUID `json:"id"`
			CreatedAt    time.Time `json:"created_at"`
			UpdatedAt    time.Time `json:"updated_at"`
			Email        string    `json:"email"`
			Token        string    `json:"token"`
			RefreshToken string    `json:"refresh_token"`
			IsChirpyRed  bool      `json:"is_chirpy_red"`
		}

		// decode into struct
		decoder := json.NewDecoder(r.Body)
		payload := Payload{}
		err := decoder.Decode(&payload)
		if err != nil {
			utils.RespondJSONError(w, http.StatusInternalServerError, "data could not be decode")
			return
		}
		// default duration
		payload.ExpiresInSeconds = time.Duration(3600 * time.Second)

		// lookup for the user
		user, err := apiCfg.db.UserExists(r.Context(), payload.Email)
		if err != nil {
			utils.RespondJSONError(w, 401, "Unauthorized")
			return
		}

		// check the password
		passwordMatch, err := auth.CheckPasswordHash(payload.Password, user.HashedPassword)
		// if not response with 401 Unauthorized
		if err != nil || passwordMatch == false {
			utils.RespondJSONError(w, 401, "Unauthorized")
			return
		}

		// Create a new jwt token for the user
		jwtToken, err := auth.MakeJWT(user.ID, apiCfg.secret, payload.ExpiresInSeconds)
		if err != nil {
			utils.RespondJSONError(w, http.StatusInternalServerError, "could not create token auth")
			return
		}
		// create a new refresh token
		refreshToken, err := auth.MakeRefreshToken()
		if err != nil {
			utils.RespondJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		// insert in refresh tokens table
		err = apiCfg.db.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
			Token:     refreshToken,
			UserID:    user.ID,
			ExpiresAt: time.Now().UTC().AddDate(0, 0, 60),
			RevokedAt: sql.NullTime{Valid: false},
		})

		// response with id, created at, updated at, email
		utils.RespondJSON(w, 200, ResponseUser{
			ID:           user.ID,
			CreatedAt:    user.CreatedAt,
			UpdatedAt:    user.UpdatedAt,
			Email:        user.Email,
			Token:        jwtToken,
			RefreshToken: refreshToken,
			IsChirpyRed:  user.IsChirpyRed,
		})
	})

	mux.HandleFunc("POST /api/refresh", func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			utils.RespondJSONError(w, http.StatusBadRequest, "Bad Request")
			return
		}

		userID, err := apiCfg.db.RefreshTokenExists(r.Context(), token)
		if err != nil {
			utils.RespondJSONError(w, 401, "token does not exists or expired")
			return
		}

		// create a new refreshtoken
		newJWT, err := auth.MakeJWT(userID, apiCfg.secret, time.Hour)
		if err != nil {
			utils.RespondJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		utils.RespondJSON(w, 200, map[string]string{"token": newJWT})

	})

	mux.HandleFunc("POST /api/revoke", func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			utils.RespondJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		err = apiCfg.db.RevokeToken(r.Context(), token)
		if err != nil {
			utils.RespondJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		utils.RespondJSON(w, 204, "")
	})

	mux.HandleFunc("PUT /api/users", func(w http.ResponseWriter, r *http.Request) {
		// respond with 401 to any error
		// get the header token
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			utils.RespondJSONError(w, 401, err.Error())
			return
		}

		userID, err := auth.ValidateJWT(token, apiCfg.secret)
		if err != nil {
			utils.RespondJSONError(w, 401, err.Error())
			return
		}

		type RequestBody struct {
			Password string `json:"password"`
			Email    string `json:"email"`
		}

		type ResponseBody struct {
			UserID uuid.UUID `json:"user_id"`
			Email  string    `json:"email"`
		}

		// get the password and email
		decoder := json.NewDecoder(r.Body)
		reqBody := RequestBody{}
		err = decoder.Decode(&reqBody)
		if err != nil {
			utils.RespondJSONError(w, 401, err.Error())
			return
		}
		// hash the password and update password and email
		hashedPassword, err := auth.HashPassword(reqBody.Password)
		if err != nil {
			utils.RespondJSONError(w, 401, err.Error())
			return
		}

		// update
		err = apiCfg.db.UpdateUserData(r.Context(), database.UpdateUserDataParams{
			HashedPassword: hashedPassword,
			Email:          reqBody.Email,
			ID:             userID,
		})

		if err != nil {
			utils.RespondJSONError(w, 401, err.Error())
			return
		}

		// respond with 200 when success and with the updated user info
		utils.RespondJSON(w, 200, ResponseBody{UserID: userID, Email: reqBody.Email})
	})

	mux.HandleFunc("DELETE /api/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) {
		// This is an authenticated endpoint, so be sure to check the token in the header.
		// Only allow the deletion of a chirp if the user is the author of the chirp.
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			utils.RespondJSONError(w, 401, "error getting access token")
			return
		}

		// authenticate the token
		userID, err := auth.ValidateJWT(token, apiCfg.secret)
		if err != nil {
			utils.RespondJSONError(w, 401, "error validating token")
			return
		}

		path := r.URL.Path
		parts := strings.Split(path, "/")
		if len(parts) != 4 {
			utils.RespondJSONError(w, 401, "there's no chirp ID")
			return
		}

		chirpID := parts[3]
		chirpUUID, err := uuid.Parse(chirpID)
		if len(parts) != 4 {
			utils.RespondJSONError(w, 401, "error parsing chirpID")
			return
		}

		// DELETE the chirp
		_, err = apiCfg.db.DeleteSingleChirp(r.Context(), database.DeleteSingleChirpParams{
			ID:     chirpUUID,
			UserID: userID,
		})
		if err != nil {
			utils.RespondJSONError(w, 403, "chirp not found")
			return
		}

		if err == sql.ErrNoRows {
			utils.RespondJSONError(w, 403, "not authorized")
			return
		}

		utils.RespondJSON(w, 204, "")
		// If they are not, return a 403 status code.
		// If the chirp is deleted successfully, return a 204 status code.
		// If the chirp is not found, return a 404 status code.
	})

	mux.HandleFunc("POST /api/polka/webhooks", func(w http.ResponseWriter, r *http.Request) {
		apiKey, err := auth.GetAPIKey(r.Header)
		if err != nil {
			utils.RespondJSONError(w, 401, "error getting the header's key")
			return
		}

		if apiKey != apiCfg.polkakey {
			utils.RespondJSONError(w, 401, "keys does not match")
			return
		}

		type EventData struct {
			UserID uuid.UUID `json:"user_id"`
		}
		type BodyRequest struct {
			Event string    `json:"event"`
			Data  EventData `json:"data"`
		}

		decoder := json.NewDecoder(r.Body)
		bodyRequest := BodyRequest{}
		err = decoder.Decode(&bodyRequest)
		if err != nil {
			utils.RespondJSONError(w, http.StatusInternalServerError, "error decoding request")
			return
		}

		log.Println(bodyRequest.Data.UserID)

		if bodyRequest.Event != "user.upgraded" {
			utils.RespondJSON(w, 204, "not user upgrade")
			return
		}

		err = apiCfg.db.UpdateChirpyRed(r.Context(), bodyRequest.Data.UserID)
		if err != nil {
			utils.RespondJSONError(w, 404, err.Error())
			return
		}
		if err == sql.ErrNoRows {
			utils.RespondJSONError(w, 404, "user can't be found")
			return
		}

		utils.RespondJSON(w, 204, "everything ok")
	})

	apiCfg.secret = os.Getenv("SECRET")
	apiCfg.polkakey = os.Getenv("POLKA_KEY")

	s := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	log.Print("Initializing server...")
	log.Fatal(s.ListenAndServe())
}

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	secret         string
	polkakey       string
}

func (cfg *apiConfig) middleWareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)

		next.ServeHTTP(w, r)
	})
}
