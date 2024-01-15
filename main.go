package main

import (
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtKey = []byte("enigma_secret_key")

type Claims struct {
	Role  string `json:"role"`
	Email string `json:"email"`
	jwt.RegisteredClaims
}

func main() {
	fmt.Println("Hello, World!")
	// login
	// if valid generate new JWT
	claim := &Claims{
		Role:  "admin",
		Email: "beni@example.com",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Second)),
			Issuer:    "EgnigmaCamp",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(tokenString)

	// tokenString = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4iLCJlbWFpbCI6ImJlbmlAZXhhbXBsZS5jb20iLCJpc3MiOiJFZ25pZ21hQ2FtcCIsImV4cCI6MTcwNTMwMjAyOH0.6fHJZJDEMuFAkYoGBlwzPOxhOBMoFRxxy0aXfH6F8JM`
	// GET JWT
	getClaim := &Claims{}
	getToken, err := jwt.ParseWithClaims(tokenString, getClaim, func(t *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		fmt.Println(err)
	} else if claims, ok := getToken.Claims.(*Claims); ok {
		fmt.Println(claims.Role, claims.Email, claims.ExpiresAt, claims.Issuer)
	} else {
		log.Fatal("unknown claims type, cannot proceed")
	}
	if !getToken.Valid {
		fmt.Println("invalid token")
	}
	// Validate JWT
}
