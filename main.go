package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var jwtKey = []byte("enigma_secret_key")

type Claims struct {
	Role  string `json:"role"`
	Email string `json:"email"`
	jwt.RegisteredClaims
}

type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"Password"`
}

func checkUser(email string, password string) (User, error) {
	for _, user := range users {
		if user.Email == email && user.Password == password {
			return user, nil
		}
	}

	return User{}, fmt.Errorf("User not found or invalid credential")
}

func loginHandler(c *gin.Context) {
	var cred Credentials
	err := c.ShouldBindJSON(&cred)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	user, err := checkUser(cred.Email, cred.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
		return
	}
	claim := &Claims{
		Role:  user.Role,
		Email: user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			Issuer:    "EgnigmaCamp",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"token": tokenString,
	})
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
	}
}

var users = []User{
	{
		Email:    "beni@example.com",
		Password: "rahasia",
		Role:     "admin",
	},
	{
		Email:    "sasuke@example.com",
		Password: "rahasia",
		Role:     "user",
	},
}

func main() {
	router := gin.Default()
	router.POST("/login", loginHandler)

	router.Use(authMiddleware())
	router.Run(":8080")
	// login
	// if valid generate new JWT
	// tokenString = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4iLCJlbWFpbCI6ImJlbmlAZXhhbXBsZS5jb20iLCJpc3MiOiJFZ25pZ21hQ2FtcCIsImV4cCI6MTcwNTMwMjAyOH0.6fHJZJDEMuFAkYoGBlwzPOxhOBMoFRxxy0aXfH6F8JM`
	// GET JWT
	// getClaim := &Claims{}
	// getToken, err := jwt.ParseWithClaims(tokenString, getClaim, func(t *jwt.Token) (interface{}, error) {
	// 	return jwtKey, nil
	// })
	// if err != nil {
	// 	fmt.Println(err)
	// } else if claims, ok := getToken.Claims.(*Claims); ok {
	// 	fmt.Println(claims.Role, claims.Email, claims.ExpiresAt, claims.Issuer)
	// } else {
	// 	log.Fatal("unknown claims type, cannot proceed")
	// }
	// if !getToken.Valid {
	// 	fmt.Println("invalid token")
	// }
	// Validate JWT
}
