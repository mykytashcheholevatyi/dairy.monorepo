package main

import (
    "context"
    "database/sql"
    "fmt"
    "net/http"
    "os"
    "golang.org/x/crypto/bcrypt"
    "github.com/dgrijalva/jwt-go"
    "github.com/gorilla/mux"
    _ "github.com/lib/pq" // PostgreSQL driver
)

// Config структура для хранения конфигурации приложения.
type Config struct {
    DatabaseURL string // URL подключения к базе данных
}

// LoadConfig функция для загрузки конфигурации из переменных окружения.
func LoadConfig() *Config {
    return &Config{
        DatabaseURL: os.Getenv("DATABASE_URL"),
    }
}

// User структура для пользователя.
type User struct {
    ID       int
    Username string
    Password string // Хэшированный пароль
}

// DiaryEntry структура для записи в дневнике.
type DiaryEntry struct {
    ID        int
    UserID    int
    Title     string
    Content   string
    Timestamp string
}

// InitDB функция для инициализации и подключения к базе данных.
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

// HealthCheckHandler обрабатывает запросы на проверку здоровья приложения.
func HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("OK"))
}

// UserRepository интерфейс, определяющий методы для работы с пользователями в базе данных.
type UserRepository interface {
    CreateUser(ctx context.Context, user *User) error
    GetUserByUsername(ctx context.Context, username string) (*User, error)
}

// userRepository структура, реализующая UserRepository интерфейс.
type userRepository struct {
    db *sql.DB
}

// NewUserRepository функция для создания нового экземпляра userRepository.
func NewUserRepository(db *sql.DB) UserRepository {
    return &userRepository{db: db}
}

// CreateUser метод для создания нового пользователя в базе данных.
func (r *userRepository) CreateUser(ctx context.Context, user *User) error {
    _, err := r.db.ExecContext(ctx, "INSERT INTO users (username, password) VALUES ($1, $2)", user.Username, user.Password)
    return err
}

// GetUserByUsername метод для получения пользователя из базы данных по его имени.
func (r *userRepository) GetUserByUsername(ctx context.Context, username string) (*User, error) {
    var user User
    err := r.db.QueryRowContext(ctx, "SELECT id, username, password FROM users WHERE username = $1", username).Scan(&user.ID, &user.Username, &user.Password)
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, nil // Пользователь не найден
        }
        return nil, err
    }
    return &user, nil
}

// HashPassword функция для хэширования пароля пользователя.
func HashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
    return string(bytes), err
}

// Authenticate метод для проверки введенного пароля по хэшированному паролю в базе данных.
func (u *User) Authenticate(password string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
    return err == nil
}

// GenerateToken создает JWT токен на основе переданных данных.
func GenerateToken(userID int, jwtSecret string) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "userID": userID,
    })
    return token.SignedString([]byte(jwtSecret))
}

// ParseToken проверяет и разбирает JWT токен.
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

// CreateDiaryEntry создает новую запись в дневнике.
func CreateDiaryEntry(w http.ResponseWriter, r *http.Request) {
    // Ваша логика создания новой записи в дневнике здесь
}

// GetDiaryEntry получает информацию о конкретной записи в дневнике.
func GetDiaryEntry(w http.ResponseWriter, r *http.Request) {
    // Ваша логика получения информации о конкретной записи в дневнике здесь
}

// UpdateDiaryEntry обновляет информацию о конкретной записи в дневнике.
func UpdateDiaryEntry(w http.ResponseWriter, r *http.Request) {
    // Ваша логика обновления информации о конкретной записи в дневнике здесь
}

func main() {
    config := LoadConfig()

    db, err := InitDB(config.DatabaseURL)
    if err != nil {
        fmt.Println("Ошибка подключения к базе данных:", err)
        return
    }
    defer db.Close()

    // Роутер для обработки запросов
    r := mux.NewRouter()

    // Обработчики для работы с пользователем
    r.HandleFunc("/register", RegisterUser).Methods("POST")
    r.HandleFunc("/login", LoginUser).Methods("POST")

    // Обработчики для работы с записями в дневнике
    r.HandleFunc("/diary/entry", CreateDiaryEntry).Methods("POST")
    r.HandleFunc("/diary/entry/{id}", GetDiaryEntry).Methods("GET")
    r.HandleFunc("/diary/entry/{id}", UpdateDiaryEntry).Methods("PUT")

    // Обработчик проверки здоровья приложения
    r.HandleFunc("/health", HealthCheckHandler)

    fmt.Println("Сервер запущен на порту 8080")
    if err := http.ListenAndServe(":8080", r); err != nil {
        fmt.Println("Ошибка запуска сервера:", err)
    }
}

// RegisterUser регистрирует нового пользователя.
func RegisterUser(w http.ResponseWriter, r *http.Request) {
    // Ваша логика регистрации нового пользователя здесь
}

// LoginUser аутентифицирует пользователя и выдает ему JWT токен.
func LoginUser(w http.ResponseWriter, r *http.Request) {
    // Ваша логика аутентификации пользователя здесь
}
