package repository

import (
    "context"
    "database/sql"
    "errors"
    // Импорт других необходимых пакетов
)

// UserRepository - интерфейс, определяющий методы для работы с пользователями в базе данных.
type UserRepository interface {
    CreateUser(ctx context.Context, user *User) error
    GetUserByUsername(ctx context.Context, username string) (*User, error)
    // Другие методы работы с пользователями...
}

// userRepository - структура, реализующая UserRepository интерфейс.
type userRepository struct {
    db *sql.DB
}

// NewUserRepository - функция для создания нового экземпляра userRepository.
func NewUserRepository(db *sql.DB) UserRepository {
    return &userRepository{
        db: db,
    }
}

// CreateUser - метод для создания нового пользователя в базе данных.
func (r *userRepository) CreateUser(ctx context.Context, user *User) error {
    // Проверка, что пользователь с таким именем уже существует
    existingUser, err := r.GetUserByUsername(ctx, user.Username)
    if err == nil && existingUser != nil {
        return errors.New("user already exists")
    }

    // Вставка данных нового пользователя в базу данных
    _, err = r.db.ExecContext(ctx, "INSERT INTO users (username, password) VALUES (?, ?)", user.Username, user.Password)
    if err != nil {
        return err
    }

    return nil
}

// GetUserByUsername - метод для получения пользователя из базы данных по его имени.
func (r *userRepository) GetUserByUsername(ctx context.Context, username string) (*User, error) {
    var user User
    err := r.db.QueryRowContext(ctx, "SELECT id, username, password FROM users WHERE username = ?", username).Scan(&user.ID, &user.Username, &user.Password)
    if err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            return nil, nil // Пользователь не найден
        }
        return nil, err
    }
    return &user, nil
}

// Другие методы работы с пользователями…

