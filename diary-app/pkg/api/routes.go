package api

import (
    "net/http"
)

// RegisterRoutes регистрирует маршруты для обработки HTTP-запросов.
func RegisterRoutes() {
    // Маршрут для работы с записями дневника
    http.HandleFunc("/api/entries", handlers.HandleEntries)
    http.HandleFunc("/api/entries/:id", handlers.HandleEntryByID)
    
    // Маршрут для работы с пользователями
    http.HandleFunc("/api/users/register", userHandlers.HandleRegistration)
    http.HandleFunc("/api/users/login", userHandlers.HandleLogin)
    http.HandleFunc("/api/users/:id", userHandlers.HandleUserProfile)
    
    // Маршрут для проверки здоровья приложения
    http.HandleFunc("/healthcheck", healthCheckHandler)
}

// healthCheckHandler обрабатывает запросы на проверку здоровья приложения.
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
    // Ваша логика проверки здоровья приложения здесь
    // Например, проверка доступности базы данных, сервисов и т.д.
    
    // Отправляем ответ об успешной проверке здоровья
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("OK"))
}
