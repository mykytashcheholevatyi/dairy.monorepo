package main

import (
    "context"
    "database/sql"
    "os"
    "testing"
    "time"

    _ "github.com/lib/pq"
)

func TestUserDiary(t *testing.T) {
    // Подготовка конфигурации
    config := &Config{
        DatabaseURL: os.Getenv("DATABASE_URL"), // Переменная окружения для URL базы данных
        JWTSecret:   "your-jwt-secret",          // Секрет для генерации JWT токенов
    }

    // Подключение к базе данных
    db, err := InitDB(config.DatabaseURL)
    if err != nil {
        t.Fatalf("ошибка подключения к базе данных: %v", err)
    }
    defer db.Close()

    // Инициализация репозитория пользователей
    userRepo := NewUserRepository(db)

    // Тест создания пользователя
    ctx := context.Background()
    user := &User{
        Username: "testuser",
        Password: "testpassword",
    }
    if err := userRepo.CreateUser(ctx, user); err != nil {
        t.Fatalf("ошибка создания пользователя: %v", err)
    }

    // Проверка существования созданного пользователя
    createdUser, err := userRepo.GetUserByUsername(ctx, user.Username)
    if err != nil {
        t.Fatalf("ошибка получения пользователя: %v", err)
    }
    if createdUser == nil {
        t.Fatalf("пользователь не был создан")
    }

    // Тест создания записи в дневнике
    diaryRepo := NewDiaryRepository(db)
    entry := &DiaryEntry{
        UserID:    createdUser.ID,
        Date:      time.Now(),
        Text:      "test diary entry",
    }
    if err := diaryRepo.CreateEntry(ctx, entry); err != nil {
        t.Fatalf("ошибка создания записи в дневнике: %v", err)
    }

    // Проверка существования созданной записи в дневнике
    entries, err := diaryRepo.GetEntriesByUserID(ctx, createdUser.ID)
    if err != nil {
        t.Fatalf("ошибка получения записей из дневника: %v", err)
    }
    if len(entries) == 0 {
        t.Fatalf("запись в дневнике не была создана")
    }

    // Тест удаления пользователя и записи в дневнике
    if err := userRepo.DeleteUser(ctx, createdUser.ID); err != nil {
        t.Fatalf("ошибка удаления пользователя: %v", err)
    }
    entries, err = diaryRepo.GetEntriesByUserID(ctx, createdUser.ID)
    if err != nil {
        t.Fatalf("ошибка получения записей из дневника после удаления пользователя: %v", err)
    }
    if len(entries) != 0 {
        t.Fatalf("записи в дневнике не были удалены после удаления пользователя")
    }
}
