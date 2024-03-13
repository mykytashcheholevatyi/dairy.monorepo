package main

import (
    "context"
    "database/sql"
    "encoding/json"
    "fmt"
    "net/http"
    "os"

    "github.com/dgrijalva/jwt-go"
    "github.com/gorilla/mux"
    _ "github.com/lib/pq"
    "golang.org/x/crypto/bcrypt"
)

// Config holds the application configuration.
type Config struct {
    DatabaseURL string // Database connection URL
    JWTSecret   string // Secret for JWT token generation
}

// LoadConfig loads configuration from environment variables.
func LoadConfig() *Config {
    return &Config{
        DatabaseURL: os.Getenv("DATABASE_URL"),
        JWTSecret:   os.Getenv("JWT_SECRET"),
    }
}

// User represents a user entity.
type User struct {
    ID       int
    Username string
    Password string // Hashed password
}

// DiaryEntry represents a diary entry entity.
type DiaryEntry struct {
    ID        int
    UserID    int
    Title     string
    Content   string
    Timestamp string
}

// InitDB initializes and connects to the database.
func InitDB(databaseURL string) (*sql.DB, error) {
    db, err := sql.Open("postgres", databaseURL)
    if err != nil {
        return nil, err
    }
    if err = db.Ping(); err != nil {
        return nil, err
    }
    return db, nil
}

// HealthCheckHandler handles health check requests.
func HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("OK"))
}

// UserRepository defines methods for user database operations.
type UserRepository interface {
    CreateUser(ctx context.Context, user *User) error
    GetUserByUsername(ctx context.Context, username string) (*User, error)
}

// userRepository implements UserRepository interface.
type userRepository struct {
    db *sql.DB
}

// NewUserRepository creates a new userRepository instance.
func NewUserRepository(db *sql.DB) UserRepository {
    return &userRepository{db: db}
}

// CreateUser creates a new user in the database.
func (r *userRepository) CreateUser(ctx context.Context, user *User) error {
    _, err := r.db.ExecContext(ctx, "INSERT INTO users (username, password) VALUES ($1, $2)", user.Username, user.Password)
    return err
}

// GetUserByUsername retrieves a user from the database by username.
func (r *userRepository) GetUserByUsername(ctx context.Context, username string) (*User, error) {
    var user User
    err := r.db.QueryRowContext(ctx, "SELECT id, username, password FROM users WHERE username = $1", username).Scan(&user.ID, &user.Username, &user.Password)
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, nil // User not found
        }
        return nil, err
    }
    return &user, nil
}

// HashPassword hashes user password.
func HashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
    return string(bytes), err
}

// Authenticate checks if the entered password matches the hashed password in the database.
func (u *User) Authenticate(password string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
    return err == nil
}

// GenerateToken creates a JWT token based on the provided data.
func GenerateToken(userID int, jwtSecret string) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "userID": userID,
    })
    return token.SignedString([]byte(jwtSecret))
}

// ParseToken verifies and parses the JWT token.
func ParseToken(tokenString, jwtSecret string) (int, error) {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        return []byte(jwtSecret), nil
    })

    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        userID := int(claims["userID"].(float64))
        return userID, nil
    } else {
        return 0, err
    }
}

// CreateDiaryEntry creates a new diary entry.
func CreateDiaryEntry(w http.ResponseWriter, r *http.Request) {
    // Parsing data from the request
    var entry DiaryEntry
    err := json.NewDecoder(r.Body).Decode(&entry)
    if err != nil {
        http.Error(w, "Error reading request data", http.StatusBadRequest)
        return
    }

    // Your logic for creating a new diary entry goes here
}

// GetDiaryEntry retrieves information about a specific diary entry.
func GetDiaryEntry(w http.ResponseWriter, r *http.Request) {
    // Parsing request parameter (e.g., entry ID)
    entryID := mux.Vars(r)["id"]

    // Your logic for retrieving information about a specific diary entry goes here
}

// UpdateDiaryEntry updates information about a specific diary entry.
func UpdateDiaryEntry(w http.ResponseWriter, r *http.Request) {
    // Parsing data from the request
    var entry DiaryEntry
    err := json.NewDecoder(r.Body).Decode(&entry)
    if err != nil {
        http.Error(w, "Error reading request data", http.StatusBadRequest)
        return
    }

    // Your logic for updating information about a specific diary entry goes here
}

// RegisterUser registers a new user.
func RegisterUser(w http.ResponseWriter, r *http.Request) {
    // Parsing data from the request
    var user User
    err := json.NewDecoder(r.Body).Decode(&user)
    if err != nil {
        http.Error(w, "Error reading request data", http.StatusBadRequest)
        return
    }

    // Hashing user password
    hashedPassword, err := HashPassword(user.Password)
    if err != nil {
        http.Error(w, "Error hashing password", http.StatusInternalServerError)
        return
    }
    user.Password = hashedPassword

    // Creating a new user in the database
    err = userRepository.CreateUser(context.Background(), &user)
    if err != nil {
        http.Error(w, "Error creating user", http.StatusInternalServerError)
        return
    }

    // Sending a response about successful registration
    w.WriteHeader(http.StatusCreated)
}

// LoginUser authenticates a user and issues a JWT token.
func LoginUser(w http.ResponseWriter, r *http.Request) {
    // Parsing data from the request
    var credentials struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }
    err := json.NewDecoder(r.Body).Decode(&credentials)
    if err != nil {
        http.Error(w, "Error reading request data", http.StatusBadRequest)
        return
    }

    // Retrieving the user from the database by username
    user, err := userRepository.GetUserByUsername(context.Background(), credentials.Username)
    if err != nil {
        http.Error(w, "Error getting user", http.StatusInternalServerError)
        return
    }
    if user == nil {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    // Checking the password
    if !user.Authenticate(credentials.Password) {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    // Creating JWT token
    token, err := GenerateToken(user.ID, config.JWTSecret)
    if err != nil {
        http.Error(w, "Error generating JWT token", http.StatusInternalServerError)
        return
    }

    // Sending the JWT token in the response
    json.NewEncoder(w).Encode(map[string]string{"token": token})
}

var (
    config         = LoadConfig()
    db, _          = InitDB(config.DatabaseURL)
    userRepository = NewUserRepository(db)
)

func main() {
    // Router for handling requests
    r := mux.NewRouter()

    // Handlers for user operations
    r.HandleFunc("/register", RegisterUser).Methods("POST")
    r.HandleFunc("/login", LoginUser).Methods("POST")

    // Handlers for diary entry operations
    r.HandleFunc("/diary/entry", CreateDiaryEntry).Methods("POST")
    r.HandleFunc("/diary/entry/{id}", GetDiaryEntry).Methods("GET")
    r.HandleFunc("/diary/entry/{id}", UpdateDiaryEntry).Methods("PUT")

    // Handler for health check
    r.HandleFunc("/health", HealthCheckHandler)

    fmt.Println("Server is running on port 8080")
    if err := http.ListenAndServe(":8080", r); err != nil {
        fmt.Println("Error starting the server:", err)
    }
}
