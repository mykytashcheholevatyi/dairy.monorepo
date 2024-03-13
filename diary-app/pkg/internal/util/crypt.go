package util

import (
    "golang.org/x/crypto/bcrypt"
    // Импортируйте другие необходимые пакеты
)

// HashPassword хэширует пароль с использованием bcrypt.
func HashPassword(password string) (string, error) {
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return "", err
    }
    return string(hashedPassword), nil
}

// ComparePassword сравнивает хэшированный пароль с обычным паролем.
func ComparePassword(hashedPassword, password string) error {
    return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

