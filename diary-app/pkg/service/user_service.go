package service

import (
    "context"
    // Импорт других необходимых пакетов
)

// UserService - интерфейс, определяющий методы для работы с пользователями.
type UserService interface {
    RegisterUser(ctx context.Context, username, password string) error
    // Другие методы работы с пользователями...
}

// userService - структура, реализующая UserService интерфейс.
type userService struct {
    userRepo UserRepository
}

// NewUserService - функция для создания нового экземпляра userService.
func NewUserService(userRepo UserRepository) UserService {
    return &userService{
        userRepo: userRepo,
    }
}

// RegisterUser - метод для регистрации нового пользователя.
func (s *userService) RegisterUser(ctx context.Context, username, password string) error {
    // Проверка наличия пользователя с таким же именем
    _, err := s.userRepo.GetUserByUsername(ctx, username)
    if err != nil {
        return err
    }

    // Создание нового пользователя
    newUser, err := NewUser(username, password)
    if err != nil {
        return err
    }

    // Сохранение пользователя в БД
    err = s.userRepo.CreateUser(ctx, newUser)
    if err != nil {
        return err
    }

    return nil
}

// Другие методы работы с пользователями…

