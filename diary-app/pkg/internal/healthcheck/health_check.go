package main

import (
    "net/http"
)

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
    // Ваша логика проверки здоровья приложения
    // Например, проверка соединения с базой данных или других сервисов

    // Если проверка прошла успешно, верните статус 200 OK
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("OK"))
}

func main() {
    // Регистрация обработчика для проверки здоровья по маршруту /health
    http.HandleFunc("/health", healthCheckHandler)

    // Добавьте другие обработчики и настройте ваш сервер как обычно
    // ...

    // Запустите ваш сервер
    http.ListenAndServe(":8080", nil)
}
