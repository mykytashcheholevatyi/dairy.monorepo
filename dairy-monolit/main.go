package main

import (
    "context"
    "database/sql"
    "encoding/json"
    "fmt"
    "net/http"
    "os"
    "time"

    "github.com/dgrijalva/jwt-go"
    "github.com/gorilla/mux"
    _ "github.com/lib/pq"
    "golang.org/x/crypto/bcrypt"
)

type Config struct {
    DatabaseURL string
    JWTSecret   string
}

func LoadConfig() *Config {
    return &Config{
        DatabaseURL: os.Getenv("DATABASE_URL"),
        JWTSecret:   os.Getenv("JWT_SECRET"),
    }
}

type User struct {
    ID       int    `json:"id"`
    Username string `json:"username"`
    Password string `json:"password"`
}

type DiaryEntry struct {
    ID        int    `json:"id"`
    UserID    int    `json:"user_id"`
    Title     string `json:"title"`
    Content   string `json:"content"`
    Timestamp string `json:"timestamp"`
}

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

func HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("OK"))
}

type UserRepository interface {
    CreateUser(ctx context.Context, user *User) error
    GetUserByUsername(ctx context.Context, username string) (*User, error)
}

type userRepository struct {
    db *sql.DB
}

func NewUserRepository(db *sql.DB) UserRepository {
    return &userRepository{db: db}
}

func (r *userRepository) CreateUser(ctx context.Context, user *User) error {
    _, err := r.db.ExecContext(ctx, "INSERT INTO users (username, password) VALUES ($1, $2)", user.Username, user.Password)
    return err
}

func (r *userRepository) GetUserByUsername(ctx context.Context, username string) (*User, error) {
    var user User
    err := r.db.QueryRowContext(ctx, "SELECT id, username, password FROM users WHERE username = $1", username).Scan(&user.ID, &user.Username, &user.Password)
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, nil
        }
        return nil, err
    }
    return &user, nil
}

func HashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
    return string(bytes), err
}

func (u *User) Authenticate(password string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
    return err == nil
}

func GenerateToken(userID int, jwtSecret string) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "userID": userID,
        "exp":    time.Now().Add(time.Hour * 24).Unix(),
    })
    return token.SignedString([]byte(jwtSecret))
}

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

func CreateDiaryEntry(w http.ResponseWriter, r *http.Request) {
    var entry DiaryEntry
    err := json.NewDecoder(r.Body).Decode(&entry)
    if err != nil {
        http.Error(w, "Ошибка при чтении данных запроса", http.StatusBadRequest)
        return
    }
}

func GetDiaryEntry(w http.ResponseWriter, r *http.Request) {
    entryID := mux.Vars(r)["id"]
}

func UpdateDiaryEntry(w http.ResponseWriter, r *http.Request) {
    var entry DiaryEntry
    err := json.NewDecoder(r.Body).Decode(&entry)
    if err != nil {
        http.Error(w, "Ошибкааа при чтении данных запроса", http.StatusBadRequest)
        return
    }
}

func RegisterUser(w http.ResponseWriter, r *http.Request) {
    var user User
    err := json.NewDecoder(r.Body).Decode(&user)
    if err != nil {
        http.Error(w, "Ошибкаа при чтении данных запроса", http.StatusBadRequest)
        return
    }

    hashedPassword, err := HashPassword(user.Password)
    if err != nil {
        http.Error(w, "Ошибкаа при хэшировании пароля", http.StatusInternalServerError)
        return
    }
    user.Password = hashedPassword

    err = userRepository.CreateUser(context.Background(), &user)
    if err != nil {
        http.Error(w, "Ошибка при создании пользователя", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusCreated)
}

func LoginUser(w http.ResponseWriter, r *http.Request) {
    var credentials struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }
    err := json.NewDecoder(r.Body).Decode(&credentials)
    if err != nil {
        http.Error(w, "Ошибка при чтении данных запроса", http.StatusBadRequest)
        return
    }

    user, err := userRepository.GetUserByUsername(context.Background(), credentials.Username)
    if err != nil {
        http.Error(w, "Ошибака апри получении пользователя", http.StatusInternalServerError)
        return
    }
    if user == nil {
        http.Error(w, "Неверные учетные данные", http.StatusUnauthorized)
        return
    }

    if !user.Authenticate(credentials.Password) {
        http.Error(w, "Неверные учетные данные", http.StatusUnauthorized)
        return
    }

    token, err := GenerateToken(user.ID, config.JWTSecret)
    if err != nil {
        http.Error(w, "Ошибка генерации JWT токена", http.StatusInternalServerError)
        return
    }

    json.NewEncoder(w).Encode(map[string]string{"token": token})
}

var (
    config         = LoadConfig()
    db, _          = InitDB(config.DatabaseURL)
    userRepository = NewUserRepository(db)
)

func main() {
    r := mux.NewRouter()

    r.HandleFunc("/register", RegisterUser).Methods("POST")
    r.HandleFunc("/login", LoginUser).Methods("POST")
    r.HandleFunc("/diary/entry", CreateDiaryEntry).Methods("POST")
    r.HandleFunc("/diary/entry/{id}", GetDiaryEntry).Methods("GET")
    r.HandleFunc("/diary/entry/{id}", UpdateDiaryEntry).Methods("PUT")
    r.HandleFunc("/health", HealthCheckHandler)

    fmt.Println("Сервер запущен на порту 8080")
    if err := http.ListenAndServe(":8080", r); err != nil {
        fmt.Println("Ошибка запуска сервера:", err)
    }
}
func CreateDiaryEntry(w http.ResponseWriter, r *http.Request) {
    var entry DiaryEntry
    err := json.NewDecoder(r.Body).Decode(&entry)
    if err != nil {
        http.Error(w, "Ошибка при чтении данных запроса", http.StatusBadRequest)
        return
    }

    // Добавление временной метки записи
    entry.Timestamp = time.Now().Format(time.RFC3339)

    // Проверка наличия пользователя в токене
    userID, err := getUserIDFromToken(r)
    if err != nil {
        http.Error(w, "Ошибка при аутентификации пользователя", http.StatusUnauthorized)
        return
    }
    entry.UserID = userID

    // Вставка записи в бааазу данных
    err = insertDiaryEntry(&entry)
    if err != nil {
        http.Error(w, "Ошибка при создании записи в дневнике", http.StatusInternalServerError)
        return
    }

    // Отправка успешного ответа
    w.WriteHeader(http.StatusCreated)
}

func GetDiaryEntry(w http.ResponseWriter, r *http.Request) {
    // Извлечение ID записи из URL
    entryID := mux.Vars(r)["id"]

    // Получение записи из базы данных
    entry, err := getDiaryEntryByID(entryID)
    if err != nil {
        http.Error(w, "Ошибка при получении записи из дневника", http.StatusInternalServerError)
        return
    }

    // Проверка прав доступа к записи
    userID, err := getUserIDFromToken(r)
    if err != nil || entry.UserID != userID {
        http.Error(w, "Недостаточно прав доступа", http.StatusForbidden)
        return
    }

    // Отправка записи в формате JSON
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(entry)
}

func UpdateDiaryEntry(w http.ResponseWriter, r *http.Request) {
    // Извлечение ID записи из URL
    entryID := mux.Vars(r)["id"]

    // Получение записи из базы данных
    entry, err := getDiaryEntryByID(entryID)
    if err != nil {
        http.Error(w, "Ошибка при получении записи из дневника", http.StatusInternalServerError)
        return
    }

    // Проверка прав доступа к записи
    userID, err := getUserIDFromToken(r)
    if err != nil || entry.UserID != userID {
        http.Error(w, "Недостаточно прав доступа", http.StatusForbidden)
        return
    }

    // Обновление данных записи
    var updatedEntry DiaryEntry
    err = json.NewDecoder(r.Body).Decode(&updatedEntry)
    if err != nil {
        http.Error(w, "Ошибка при чтении данных запроса", http.StatusBadRequest)
        return
    }

    // Обновление заголовка и содержимого записи
    entry.Title = updatedEntry.Title
    entry.Content = updatedEntry.Content

    // Обновление записи в базе данных
    err = updateDiaryEntry(&entry)
    if err != nil {
        http.Error(w, "Ошибка при обновлении записи в дневнике", http.StatusInternalServerError)
        return
    }

    // Отправка успешного ответа
    w.WriteHeader(http.StatusOK)
}

// Функция для извлечения идентификатора пользователя из JWT токена
func getUserIDFromToken(r *http.Request) (int, error) {
    // Извлечение токена из заголовка Authorization
    tokenString := r.Header.Get("Authorization")
    if tokenString == "" {
        return 0, fmt.Errorf("токен не найден")
    }

    // Проверка и разбор JWT токена
    userID, err := ParseToken(tokenString, config.JWTSecret)
    if err != nil {
        return 0, err
    }

    return userID, nil
}


// Функция для вставки записи в базу данных
func insertDiaryEntry(entry *DiaryEntry) error {
    // Подготовка SQL запроса
    query := "INSERT INTO diary_entries (user_id, title, content, timestamp) VALUES ($1, $2, $3, $4) RETURNING id"
    
    // Выполнение SQL запроса и извлечение идентификатора созданной записи
    err := db.QueryRow(query, entry.UserID, entry.Title, entry.Content, entry.Timestamp).Scan(&entry.ID)
    if err != nil {
        return err
    }

    return nil
}




// Функция для получения записи из базы данных по ее идентификатору
func getDiaryEntryByID(entryID string) (*DiaryEntry, error) {
    var entry DiaryEntry

    // Подготовка SQL запроса
    query := "SELECT id, user_id, title, content, timestamp FROM diary_entries WHERE id = $1"

    // Выполнение SQL запроса
    err := db.QueryRow(query, entryID).Scan(&entry.ID, &entry.UserID, &entry.Title, &entry.Content, &entry.Timestamp)
    if err != nil {
        return nil, err
    }

    return &entry, nil
}

// Функция для обновления записи в базе данных
func updateDiaryEntry(entry *DiaryEntry) error {
    // Подготовка SQL запроса
    query := "UPDATE diary_entries SET title = $1, content = $2 WHERE id = $3"
    
    // Выполнение SQL запроса
    _, err := db.Exec(query, entry.Title, entry.Content, entry.ID)
    if err != nil {
        return err
    }

    return nil
}

func DeleteDiaryEntry(w http.ResponseWriter, r *http.Request) {
    // Извлечение ID записи из URL
    entryID := mux.Vars(r)["id"]

    // Получение записи из базы данных
    entry, err := getDiaryEntryByID(entryID)
    if err != nil {
        http.Error(w, "Ошибка при получении записи из дневника", http.StatusInternalServerError)
        return
    }

    // Проверка прав доступа к записи
    userID, err := getUserIDFromToken(r)
    if err != nil || entry.UserID != userID {
        http.Error(w, "Недостаточно прав доступа", http.StatusForbidden)
        return
    }

    // Удаление записи из базы данных
    err = deleteDiaryEntry(entryID)
    if err != nil {
        http.Error(w, "Ошибка при удалении записи из дневника", http.StatusInternalServerError)
        return
    }

    // Отправка успешного ответа
    w.WriteHeader(http.StatusOK)
}

func GetAllDiaryEntries(w http.ResponseWriter, r *http.Request) {
    // Получение идентификатора пользователя из токена
    userID, err := getUserIDFromToken(r)
    if err != nil {
        http.Error(w, "Ошибка при аутентификации пользователя", http.StatusUnauthorized)
        return
    }

    // Получение всех записей из базы данных для данного пользователя
    entries, err := getAllDiaryEntriesForUser(userID)
    if err != nil {
        http.Error(w, "Ошибка при получении записей из дневника", http.StatusInternalServerError)
        return
    }

    // Отправка списка записей в формате JSON
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(entries)
}

func deleteDiaryEntry(entryID string) error {
    // Подготовка SQL запроса для удаления записи из базы данных
    query := "DELETE FROM diary_entries WHERE id = $1"

    // Выполнение SQL запроса
    _, err := db.Exec(query, entryID)
    if err != nil {
        return err
    }

    return nil
}

func getAllDiaryEntriesForUser(userID int) ([]DiaryEntry, error) {
    // Подготовка SQL запроса для получения всех записей данного пользователя
    query := "SELECT id, user_id, title, content, timestamp FROM diary_entries WHERE user_id = $1"

    // Выполнение SQL запроса
    rows, err := db.Query(query, userID)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    // Считывание записей из результата запроса
    var entries []DiaryEntry
    for rows.Next() {
        var entry DiaryEntry
        if err := rows.Scan(&entry.ID, &entry.UserID, &entry.Title, &entry.Content, &entry.Timestamp); err != nil {
            return nil, err
        }
        entries = append(entries, entry)
    }
    if err := rows.Err(); err != nil {
        return nil, err
    }

    return entries, nil
}

// Добавление маршрутов для новых обработчиков
r.HandleFunc("/diary/entry/{id}", DeleteDiaryEntry).Methods("DELETE")
r.HandleFunc("/diary/entries", GetAllDiaryEntries).Methods("GET")

func GetDiaryEntry(w http.ResponseWriter, r *http.Request) {
    // Извлечение ID записи из URL
    entryID := mux.Vars(r)["id"]

    // Получение записи из базы данных
    entry, err := getDiaryEntryByID(entryID)
    if err != nil {
        http.Error(w, "Ошибка при получении записи из дневника", http.StatusInternalServerError)
        return
    }

    // Проверка прав доступа к записи
    userID, err := getUserIDFromToken(r)
    if err != nil || entry.UserID != userID {
        http.Error(w, "Недостаточно прав доступа", http.StatusForbidden)
        return
    }

    // Отправка записи в формате JSON
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(entry)
}

func UpdateUserPassword(w http.ResponseWriter, r *http.Request) {
    // Извлечение ID пользователя из токена
    userID, err := getUserIDFromToken(r)
    if err != nil {
        http.Error(w, "Ошибка при аутентификации пользователя", http.StatusUnauthorized)
        return
    }

    // Извлечение нового пароля из запроса
    var newPassword struct {
        NewPassword string `json:"new_password"`
    }
    err = json.NewDecoder(r.Body).Decode(&newPassword)
    if err != nil {
        http.Error(w, "Ошибка при чтении данных запроса", http.StatusBadRequest)
        return
    }

    // Хэширование нового пароля
    hashedPassword, err := HashPassword(newPassword.NewPassword)
    if err != nil {
        http.Error(w, "Ошибка при хэшировании пароля", http.StatusInternalServerError)
        return
    }

    // Обновление пароля в базе данных
    err = updateUserPassword(userID, hashedPassword)
    if err != nil {
        http.Error(w, "Ошибка при обновлении пароля пользователя", http.StatusInternalServerError)
        return
    }

    // Отправка успешного ответа
    w.WriteHeader(http.StatusOK)
}

func updateUserPassword(userID int, newPassword string) error {
    // Подготовка SQL запроса для обновления пароля пользователя
    query := "UPDATE users SET password = $1 WHERE id = $2"
    
    // Выполнение SQL запроса
    _, err := db.Exec(query, newPassword, userID)
    if err != nil {
        return err
    }

    return nil
}

// Добавление маршрутов для новых обработчиков
r.HandleFunc("/diary/entry/{id}", GetDiaryEntry).Methods("GET")
r.HandleFunc("/user/password", UpdateUserPassword).Methods("PUT")

func DeleteDiaryEntry(w http.ResponseWriter, r *http.Request) {
    // Извлечение ID записи из URL
    entryID := mux.Vars(r)["id"]

    // Получение записи из базы данных
    entry, err := getDiaryEntryByID(entryID)
    if err != nil {
        http.Error(w, "Ошибка при получении записи из дневника", http.StatusInternalServerError)
        return
    }

    // Проверка прав доступа к записи
    userID, err := getUserIDFromToken(r)
    if err != nil || entry.UserID != userID {
        http.Error(w, "Недостаточно прав доступа", http.StatusForbidden)
        return
    }

    // Удаление записи из базы данных
    err = deleteDiaryEntry(entryID)
    if err != nil {
        http.Error(w, "Ошибка при удалении записи из дневника", http.StatusInternalServerError)
        return
    }

    // Отправка успешного ответа
    w.WriteHeader(http.StatusOK)
}

func deleteDiaryEntry(entryID string) error {
    // Подготовка SQL запроса для удаления записи из базы данных
    query := "DELETE FROM diary_entries WHERE id = $1"

    // Выполнение SQL запроса
    _, err := db.Exec(query, entryID)
    if err != nil {
        return err
    }

    return nil
}

// Добавление маршрута для нового обработчика
r.HandleFunc("/diary/entry/{id}", DeleteDiaryEntry).Methods("DELETE")

func UpdateUserPassword(w http.ResponseWriter, r *http.Request) {
    // Извлечение ID пользователя из токена
    userID, err := getUserIDFromToken(r)
    if err != nil {
        http.Error(w, "Ошибка при аутентификации пользователя", http.StatusUnauthorized)
        return
    }

    // Извлечение нового пароля из тела запроса
    var newPassword struct {
        Password string `json:"password"`
    }
    err = json.NewDecoder(r.Body).Decode(&newPassword)
    if err != nil {
        http.Error(w, "Ошибка при чтении данных запроса", http.StatusBadRequest)
        return
    }

    // Хэширование нового пароля
    hashedPassword, err := HashPassword(newPassword.Password)
    if err != nil {
        http.Error(w, "Ошибка при хэшировании пароля", http.StatusInternalServerError)
        return
    }

    // Обновление пароля пользователя в базе данных
    err = updateUserPassword(userID, hashedPassword)
    if err != nil {
        http.Error(w, "Ошибка при обновлении пароля пользователя", http.StatusInternalServerError)
        return
    }

    // Отправка успешного ответа
    w.WriteHeader(http.StatusOK)
}

func updateUserPassword(userID int, hashedPassword string) error {
    // Подготовка SQL запроса для обновления пароля пользователя
    query := "UPDATE users SET password = $1 WHERE id = $2"

    // Выполнение SQL запроса
    _, err := db.Exec(query, hashedPassword, userID)
    if err != nil {
        return err
    }

    return nil
}

// Добавление маршрута для нового обработчика
r.HandleFunc("/user/password", UpdateUserPassword).Methods("PUT")

func CreateDiaryEntry(w http.ResponseWriter, r *http.Request) {
    var entry DiaryEntry
    err := json.NewDecoder(r.Body).Decode(&entry)
    if err != nil {
        http.Error(w, "Ошибка при чтении данных запроса", http.StatusBadRequest)
        return
    }

    // Добавление временной метки записи
    entry.Timestamp = time.Now().Format(time.RFC3339)

    // Проверка наличия пользователя в токене
    userID, err := getUserIDFromToken(r)
    if err != nil {
        http.Error(w, "Ошибка при аутентификации пользователя", http.StatusUnauthorized)
        return
    }
    entry.UserID = userID

    // Вставка записи в базу данных
    err = insertDiaryEntry(&entry)
    if err != nil {
        http.Error(w, "Ошибка при создании записи в дневнике", http.StatusInternalServerError)
        return
    }

    // Отправка созданной записи в формате JSON
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(entry)
}

func GetDiaryEntry(w http.ResponseWriter, r *http.Request) {
    // Извлечение ID записи из URL
    entryID := mux.Vars(r)["id"]

    // Получение записи из базы данных
    entry, err := getDiaryEntryByID(entryID)
    if err != nil {
        http.Error(w, "Ошибка при получении записи из дневника", http.StatusInternalServerError)
        return
    }

    // Проверка прав доступа к записи
    userID, err := getUserIDFromToken(r)
    if err != nil || entry.UserID != userID {
        http.Error(w, "Недостаточно прав доступа", http.StatusForbidden)
        return
    }

    // Отправка записи в формате JSON
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(entry)
}

// Функция для создания нового пользователя
func CreateUser(w http.ResponseWriter, r *http.Request) {
    var user User
    err := json.NewDecoder(r.Body).Decode(&user)
    if err != nil {
        http.Error(w, "Ошибка при чтении данных запроса", http.StatusBadRequest)
        return
    }

    // Хэширование пароля пользователя
    hashedPassword, err := HashPassword(user.Password)
    if err != nil {
        http.Error(w, "Ошибка при хэшировании пароля", http.StatusInternalServerError)
        return
    }
    user.Password = hashedPassword

    // Создание пользователя в базе данных
    err = userRepository.CreateUser(context.Background(), &user)
    if err != nil {
        http.Error(w, "Ошибка при создании пользователя", http.StatusInternalServerError)
        return
    }

    // Отправка успешного ответа
    w.WriteHeader(http.StatusCreated)
}

// Функция для аутентификации пользователя и генерации JWT токена
func LoginUser(w http.ResponseWriter, r *http.Request) {
    var credentials struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }
    err := json.NewDecoder(r.Body).Decode(&credentials)
    if err != nil {
        http.Error(w, "Ошибка при чтении данных запроса", http.StatusBadRequest)
        return
    }

    // Поиск пользователя в базе данных по имени пользователя
    user, err := userRepository.GetUserByUsername(context.Background(), credentials.Username)
    if err != nil {
        http.Error(w, "Ошибка при получении пользователя", http.StatusInternalServerError)
        return
    }
    if user == nil || !user.Authenticate(credentials.Password) {
        http.Error(w, "Неверные учетные данные", http.StatusUnauthorized)
        return
    }

    // Генерация JWT токена
    token, err := GenerateToken(user.ID, config.JWTSecret)
    if err != nil {
        http.Error(w, "Ошибка генерации JWT токена", http.StatusInternalServerError)
        return
    }

    // Отправка токена в формате JSON
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"token": token})
}
// Добавление маршрутов для новых обработчиков пользователей
r.HandleFunc("/user/register", CreateUser).Methods("POST")
r.HandleFunc("/user/login", LoginUser).Methods("POST")

// Функция для получения списка всех пользователей
func GetAllUsers(w http.ResponseWriter, r *http.Request) {
    // Получение всех пользователей из базы данных
    users, err := userRepository.GetAllUsers(context.Background())
    if err != nil {
        http.Error(w, "Ошибка при получении списка пользователей", http.StatusInternalServerError)
        return
    }

    // Отправка списка пользователей в формате JSON
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(users)
}

// Функция для получения пользователя по его идентификатору
func GetUserByID(w http.ResponseWriter, r *http.Request) {
    // Извлечение идентификатора пользователя из URL
    userID := mux.Vars(r)["id"]

    // Получение пользователя из базы данных
    user, err := userRepository.GetUserByID(context.Background(), userID)
    if err != nil {
        http.Error(w, "Ошибка при получении пользователя", http.StatusInternalServerError)
        return
    }

    // Проверка существования пользователя
    if user == nil {
        http.Error(w, "Пользователь не найден", http.StatusNotFound)
        return
    }

    // Отправка пользователя в формате JSON
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(user)
}

// Функция для обновления информации о пользователе
func UpdateUser(w http.ResponseWriter, r *http.Request) {
    // Извлечение идентификатора пользователя из URL
    userID := mux.Vars(r)["id"]

    // Получение данных пользователя из запроса
    var user User
    err := json.NewDecoder(r.Body).Decode(&user)
    if err != nil {
        http.Error(w, "Ошибка при чтении данных запроса", http.StatusBadRequest)
        return
    }

    // Обновление информации о пользователе в базе данных
    err = userRepository.UpdateUser(context.Background(), userID, &user)
    if err != nil {
        http.Error(w, "Ошибка при обновлении пользователя", http.StatusInternalServerError)
        return
    }

    // Отправка успешного ответа
    w.WriteHeader(http.StatusOK)
}

// Функция для удаления пользователя
func DeleteUser(w http.ResponseWriter, r *http.Request) {
    // Извлечение идентификатора пользователя из URL
    userID := mux.Vars(r)["id"]

    // Удаление пользователя из базы данных
    err := userRepository.DeleteUser(context.Background(), userID)
    if err != nil {
        http.Error(w, "Ошибка при удалении пользователя", http.StatusInternalServerError)
        return
    }

    // Отправка успешного ответа
    w.WriteHeader(http.StatusOK)
}

// Функция для создания записи в дневнике
func CreateDiaryEntry(w http.ResponseWriter, r *http.Request) {
    var entry DiaryEntry
    err := json.NewDecoder(r.Body).Decode(&entry)
    if err != nil {
        http.Error(w, "Ошибка при чтении данных запроса", http.StatusBadRequest)
        return
    }

    // Добавление временной метки записи
    entry.Timestamp = time.Now().Format(time.RFC3339)

    // Проверка наличия пользователя в токене
    userID, err := getUserIDFromToken(r)
    if err != nil {
        http.Error(w, "Ошибка при аутентификации пользователя", http.StatusUnauthorized)
        return
    }
    entry.UserID = userID

    // Вставка записи в базу данных
    err = insertDiaryEntry(&entry)
    if err != nil {
        http.Error(w, "Ошибка при создании записи в дневнике", http.StatusInternalServerError)
        return
    }

    // Отправка созданной записи в формате JSON
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(entry)
}

// Функция для получения записи из дневника
func GetDiaryEntry(w http.ResponseWriter, r *http.Request) {
    // Извлечение ID записи из URL
    entryID := mux.Vars(r)["id"]

    // Получение записи из базы данных
    entry, err := getDiaryEntryByID(entryID)
    if err != nil {
        http.Error(w, "Ошибка при получении записи из дневника", http.StatusInternalServerError)
        return
    }

    // Проверка прав доступа к записи
    userID, err := getUserIDFromToken(r)
    if err != nil || entry.UserID != userID {
        http.Error(w, "Недостаточно прав доступа", http.StatusForbidden)
        return
    }

    // Отправка записи в формате JSON
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(entry)
}

// Функция для обновления записи в дневнике
func UpdateDiaryEntry(w http.ResponseWriter, r *http.Request) {
    // Извлечение ID записи из URL
    entryID := mux.Vars(r)["id"]

    // Получение данных записи из запроса
    var entry DiaryEntry
    err := json.NewDecoder(r.Body).Decode(&entry)
    if err != nil {
        http.Error(w, "Ошибка при чтении данных запроса", http.StatusBadRequest)
        return
    }

    // Проверка прав доступа к записи
    userID, err := getUserIDFromToken(r)
    if err != nil {
        http.Error(w, "Ошибка при аутентификации пользователя", http.StatusUnauthorized)
        return
    }

    // Получение записи из базы данных
    existingEntry, err := getDiaryEntryByID(entryID)
    if err != nil {
        http.Error(w, "Ошибка при получении записи из дневника", http.StatusInternalServerError)
        return
    }

    // Проверка прав доступа к записи
    if existingEntry.UserID != userID {
        http.Error(w, "Недостаточно прав доступа", http.StatusForbidden)
        return
    }

    // Обновление данных записи
    existingEntry.Title = entry.Title
    existingEntry.Content = entry.Content

    // Обновление записи в базе данных
    err = updateDiaryEntry(existingEntry)
    if err != nil {
        http.Error(w, "Ошибка при обновлении записи в дневнике", http.StatusInternalServerError)
        return
    }

    // Отправка успешного ответа
    w.WriteHeader(http.StatusOK)
}

// Функция для удаления записи из дневника
func DeleteDiaryEntry(w http.ResponseWriter, r *http.Request) {
    // Извлечение ID записи из URL
    entryID := mux.Vars(r)["id"]

    // Получение записи из базы данных
    entry, err := getDiaryEntryByID(entryID)
    if err != nil {
        http.Error(w, "Ошибка при получении записи из дневника", http.StatusInternalServerError)
        return
    }

    // Проверка прав доступа к записи
    userID, err := getUserIDFromToken(r)
    if err != nil || entry.UserID != userID {
        http.Error(w, "Недостаточно прав доступа", http.StatusForbidden)
        return
    }

    // Удаление записи из базы данных
    err = deleteDiaryEntry(entryID)
    if err != nil {
        http.Error(w, "Ошибка при удалении записи из дневника", http.StatusInternalServerError)
        return
    }

    // Отправка успешного ответа
    w.WriteHeader(http.StatusOK)
}

// Функция для получения всех записей из дневника пользователя
func GetAllDiaryEntries(w http.ResponseWriter, r *http.Request) {
    // Получение идентификатора пользователя из токена
    userID, err := getUserIDFromToken(r)
    if err != nil {
        http.Error(w, "Ошибка при аутентификации пользователя", http.StatusUnauthorized)
        return
    }

    // Получение всех записей из базы данных для данного пользователя
    entries, err := getAllDiaryEntriesForUser(userID)
    if err != nil {
        http.Error(w, "Ошибка при получении записей из дневника", http.StatusInternalServerError)
        return
    }

    // Отправка списка записей в формате JSON
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(entries)
}

// Функция для вставки записи в базу данных
func insertDiaryEntry(entry *DiaryEntry) error {
    // Подготовка SQL запроса для вставки записи
    query := "INSERT INTO diary_entries (user_id, title, content, timestamp) VALUES ($1, $2, $3, $4) RETURNING id"
    
    // Выполнение SQL запроса
    err := db.QueryRow(query, entry.UserID, entry.Title, entry.Content, entry.Timestamp).Scan(&entry.ID)
    if err != nil {
        return err
    }

    return nil
}

// Функция для получения всех записей из дневника пользователя из базы данных
func getAllDiaryEntriesForUser(userID int) ([]DiaryEntry, error) {
    // Подготовка SQL запроса для получения всех записей данного пользователя
    query := "SELECT id, user_id, title, content, timestamp FROM diary_entries WHERE user_id = $1"

    // Выполнение SQL запроса
    rows, err := db.Query(query, userID)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    // Считывание записей из результата запроса
    var entries []DiaryEntry
    for rows.Next() {
        var entry DiaryEntry
        if err := rows.Scan(&entry.ID, &entry.UserID, &entry.Title, &entry.Content, &entry.Timestamp); err != nil {
            return nil, err
        }
        entries = append(entries, entry)
    }
    if err := rows.Err(); err != nil {
        return nil, err
    }

    return entries, nil
}

// Функция для вставки записи в дневник
func insertDiaryEntry(entry *DiaryEntry) error {
    // Подготовка SQL запроса для вставки записи
    query := "INSERT INTO diary_entries (user_id, title, content, timestamp) VALUES ($1, $2, $3, $4) RETURNING id"
    
    // Выполнение SQL запроса
    err := db.QueryRow(query, entry.UserID, entry.Title, entry.Content, entry.Timestamp).Scan(&entry.ID)
    if err != nil {
        return err
    }

    return nil
}

// Функция для обновления записи в дневнике
func updateDiaryEntry(entry *DiaryEntry) error {
    // Подготовка SQL запроса для обновления записи
    query := "UPDATE diary_entries SET title = $1, content = $2 WHERE id = $3"
    
    // Выполнение SQL запроса
    _, err := db.Exec(query, entry.Title, entry.Content, entry.ID)
    if err != nil {
        return err
    }

    return nil
}


// Функция для удаления записи из дневника
func deleteDiaryEntry(entryID string) error {
    // Подготовка SQL запроса для удаления записи
    query := "DELETE FROM diary_entries WHERE id = $1"

    // Выполнение SQL запроса
    _, err := db.Exec(query, entryID)
    if err != nil {
        return err
    }

    return nil
}

// Обработчик для удаления записи из дневника
func DeleteDiaryEntry(w http.ResponseWriter, r *http.Request) {
    // Извлечение ID записи из URL
    entryID := mux.Vars(r)["id"]

    // Получение записи из базы данных
    entry, err := getDiaryEntryByID(entryID)
    if err != nil {
        http.Error(w, "Ошибка при получении записи из дневника", http.StatusInternalServerError)
        return
    }

    // Проверка прав доступа к записи
    userID, err := getUserIDFromToken(r)
    if err != nil || entry.UserID != userID {
        http.Error(w, "Недостаточно прав доступа", http.StatusForbidden)
        return
    }

    // Удаление записи из базы данных
    err = deleteDiaryEntry(entryID)
    if err != nil {
        http.Error(w, "Ошибка при удалении записи из дневника", http.StatusInternalServerError)
        return
    }

    // Отправка успешного ответа
    w.WriteHeader(http.StatusOK)
}

// Обработчик для обновления пароля пользователя
func UpdateUserPassword(w http.ResponseWriter, r *http.Request) {
    // Извлечение ID пользователя из токена
    userID, err := getUserIDFromToken(r)
    if err != nil {
        http.Error(w, "Ошибка при аутентификации пользователя", http.StatusUnauthorized)
        return
    }

    // Извлечение нового пароля из тела запроса
    var newPassword struct {
        Password string `json:"password"`
    }
    err = json.NewDecoder(r.Body).Decode(&newPassword)
    if err != nil {
        http.Error(w, "Ошибка при чтении данных запроса", http.StatusBadRequest)
        return
    }

    // Хэширование нового пароля
    hashedPassword, err := HashPassword(newPassword.Password)
    if err != nil {
        http.Error(w, "Ошибка при хэшировании пароля", http.StatusInternalServerError)
        return
    }

    // Обновление пароля пользователя в базе данных
    err = updateUserPassword(userID, hashedPassword)
    if err != nil {
        http.Error(w, "Ошибка при обновлении пароля пользователя", http.StatusInternalServerError)
        return
    }

    // Отправка успешного ответа
    w.WriteHeader(http.StatusOK)
}

// Функция для создания записи в дневнике
func insertDiaryEntry(entry *DiaryEntry) error {
    // Подготовка SQL запроса для вставки записи
    query := "INSERT INTO diary_entries (user_id, title, content, timestamp) VALUES ($1, $2, $3, $4)"

    // Выполнение SQL запроса
    _, err := db.Exec(query, entry.UserID, entry.Title, entry.Content, entry.Timestamp)
    if err != nil {
        return err
    }

    return nil
}

// Обработчик для создания новой записи в дневнике
func CreateDiaryEntry(w http.ResponseWriter, r *http.Request) {
    var entry DiaryEntry
    err := json.NewDecoder(r.Body).Decode(&entry)
    if err != nil {
        http.Error(w, "Ошибка при чтении данных запроса", http.StatusBadRequest)
        return
    }

    // Добавление временной метки записи
    entry.Timestamp = time.Now().Format(time.RFC3339)

    // Проверка наличия пользователя в токене
    userID, err := getUserIDFromToken(r)
    if err != nil {
        http.Error(w, "Ошибка при аутентификации пользователя", http.StatusUnauthorized)
        return
    }
    entry.UserID = userID

    // Вставка записи в базу данных
    err = insertDiaryEntry(&entry)
    if err != nil {
        http.Error(w, "Ошибка при создании записи в дневнике", http.StatusInternalServerError)
        return
    }

    // Отправка созданной записи в формате JSON
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(entry)
}

// Добавление маршрутов для новых обработчиков
r.HandleFunc("/diary/entry", CreateDiaryEntry).Methods("POST")

// Обработчик для получения одной записи из дневника
func GetDiaryEntry(w http.ResponseWriter, r *http.Request) {
    // Извлечение ID записи из URL
    entryID := mux.Vars(r)["id"]

    // Получение записи из базы данных
    entry, err := getDiaryEntryByID(entryID)
    if err != nil {
        http.Error(w, "Ошибка при получении записи из дневника", http.StatusInternalServerError)
        return
    }

    // Проверка прав доступа к записи
    userID, err := getUserIDFromToken(r)
    if err != nil || entry.UserID != userID {
        http.Error(w, "Недостаточно прав доступа", http.StatusForbidden)
        return
    }

    // Отправка записи в формате JSON
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(entry)
}

// Добавление маршрута для получения одной записи из дневника
r.HandleFunc("/diary/entry/{id}", GetDiaryEntry).Methods("GET")

// Обработчик для обработки HTTP запросов
func handlerFunc(w http.ResponseWriter, r *http.Request) {
    // Ваш код обработки запросов здесь
}

func main() {
    // Регистрация обработчика для всех запросов
    http.HandleFunc("/", handlerFunc)

    // Настройка сервера и его запуск
    http.ListenAndServe(":8080", nil)
}
// Обработчик для маршрута /users
func usersHandler(w http.ResponseWriter, r *http.Request) {
    // Ваш код обработки запросов для /users
}

// Обработчик для маршрута /posts
func postsHandler(w http.ResponseWriter, r *http.Request) {
    // Ваш код обработки запросов для /posts
}

func main() {
    // Регистрация обработчиков для различных маршрутов
    http.HandleFunc("/users", usersHandler)
    http.HandleFunc("/posts", postsHandler)

    // Настройка сервера и его запуск
    http.ListenAndServe(":8080", nil)
}
// Пример проверки аутентификации пользователя
func authenticate(w http.ResponseWriter, r *http.Request) {
    // Проверка наличия токена доступа в заголовке запроса
    token := r.Header.Get("Authorization")
    if token == "" {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    // Проверка валидности токена
    if !isValidToken(token) {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }

    // Аутентификация успешна, продолжаем обработку запроса
    // Ваш код здесь
}
import (
    "database/sql"
    _ "github.com/go-sql-driver/mysql"
)

func main() {
    // Подключение к базе данных MySQL
    db, err := sql.Open("mysql", "user:password@tcp(127.0.0.1:3306)/dbname")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Выполнение запросов к базе данных
    // Ваш код здесь
}

import (
    "github.com/sirupsen/logrus"
)

// Инициализация логгера
log := logrus.New()

// Запись события
log.Info("This is an informational message")

// Запись ошибки
log.Error("This is an error message")

import (
    _ "net/http/pprof"
    "net/http"
)

// Регистрация обработчика для pprof
go func() {
    http.ListenAndServe("localhost:6060", nil)
}()

import (
    "github.com/patrickmn/go-cache"
    "time"
)

// Создание нового кэша
c := cache.New(5*time.Minute, 10*time.Minute)

// Кэширование значения
c.Set("key", "value", cache.DefaultExpiration)

// Получение значения из кэша
value, found := c.Get("key")
if found {
    // Обработка значения
}


import (
    "encoding/json"
    "github.com/go-playground/validator"
)

type User struct {
    Username string `json:"username" validate:"required"`
    Email    string `json:"email" validate:"required,email"`
}

// Создание нового валидатора
validate := validator.New()

// Парсинг JSON и валидация
var user User
jsonStr := `{"username": "john_doe", "email": "john.doe@example.com"}`
err := json.Unmarshal([]byte(jsonStr), &user)
if err != nil {
    // Обработка ошибки
}

// Валидация структуры
if err := validate.Struct(user); err != nil {
    // Обработка ошибки валидации
}


import (
    "github.com/gorilla/csrf"
    "net/http"
)

// Создание нового защитного токена
csrfMiddleware := csrf.Protect([]byte("32-byte-long-auth-key"))

// Добавление защиты CSRF к обработчику
http.Handle("/submit", csrfMiddleware(http.HandlerFunc(submitHandler)))

// Обработчик запроса
func submitHandler(w http.ResponseWriter, r *http.Request) {
    // Обработка запроса
}


// Функция, возвращающая ошибку
func doSomething() error {
    // Выполнение какой-то операции
    if err != nil {
        return fmt.Errorf("ошибка выполнения операции: %v", err)
    }
    return nil
}

// Выазов функцаии с оабработкой ошибки
if err := doSomething(); err != nil {
    // Обработка ошибки
    log.Println("Ошибка:", err)
}






