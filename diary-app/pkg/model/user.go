package model

import (
    // Импортируйте необходимые пакеты, например для работы с БД или хэширования паролей
)

// User - структура, представляющая пользователя в системе.
type User struct {
    ID       int    // Уникальный идентификатор пользователя
    Username string // Имя пользователя
    Password string // Хэшированный пароль
}

// NewUser - функция для создания нового пользователя с хэшированным паролем.
func NewUser(username, password string) (*User, error) {
    // Хэшируйте пароль пользователя здесь
    hashedPassword, err := HashPassword(password)
    if err != nil {
        return nil, err
    }

    return &User{
        Username: username,
        Password: hashedPassword,
    }, nil
}

// HashPassword - функция для хэширования пароля пользователя.
func HashPassword(password string) (string, error) {
    // Используйте надежный алгоритм хэширования, например bcrypt
}

// Authenticate - метод для проверки введенного пароля по хэшированному паролю в базе данных.
func (u *User) Authenticate(password string) bool {
    // Сравните хэшированный пароль и пароль, введенный пользователем
}

