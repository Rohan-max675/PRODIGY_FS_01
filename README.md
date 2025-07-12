# Secure Authentication System

A Node.js authentication system with JWT and bcrypt.

## Features
- User registration
- Secure login with JWT
- Password hashing with bcrypt
- Protected routes middleware

## Installation
1. Clone this repository
2. Run `npm install`
3. Create `.env` file based on `.env.example`
4. Run `npm start`

## API Endpoints
- POST `/api/auth/register` - User registration
- POST `/api/auth/login` - User login
- GET `/api/auth/protected` - Protected route (requires valid JWT)
