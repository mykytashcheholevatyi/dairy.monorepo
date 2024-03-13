package util

import (
    "github.com/dgrijalva/jwt-go"
    // Импортируйте другие необходимые пакеты
)

// GenerateToken создает JWT токен на основе переданных данных.
func GenerateToken(userID int) (string, error) {
    // Создание JWT токена
    token := jwt.New(jwt.SigningMethodHS256)
    claims := token.Claims.(jwt.MapClaims)
    claims["userID"] = userID

    // Подпись токена
    signedToken, err := token.SignedString([]byte("your-secret-key"))
    if err != nil {
        return "", err
    }

    return signedToken, nil
}

// ParseToken проверяет и разбирает JWT токен.
func ParseToken(tokenString string) (int, error) {
    // Проверка токена и извлечение данных
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        return []byte("your-secret-key"), nil
    })
    if err != nil {
        return 0, err
    }

    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok || !token.Valid {
        return 0, errors.New("invalid token")
    }

    userID := int(claims["userID"].(float64))
    return userID, nil
}

