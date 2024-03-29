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
	cookieToken, err := c.Cookie("token")
	if err != nil {
		cookieToken = tokenString
		c.SetCookie("token", cookieToken, 3600, "/", "localhost", false, true)
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "login success",
	})
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// authorHeader := c.GetHeader("Authorization")
		// if authorHeader == "" {
		// 	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		// 		"error": "Unauthorized",
		// 	})
		// 	return
		// }
		// bearerToken := strings.Split(authorHeader, " ")
		// if len(bearerToken) != 2 {
		// 	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		// 		"error": "Invalid Authorizaation Header",
		// 	})
		// 	return
		// }
		//
		// if bearerToken[0] != "Bearer" {
		// 	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		// 		"error": "Invalid Authorizaation Header",
		// 	})
		// 	return
		// }
		cookieToken, err := c.Cookie("token")
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Unauthorized",
			})
		}

		getClaim := &Claims{}
		getToken, err := jwt.ParseWithClaims(cookieToken, getClaim, func(t *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !getToken.Valid || getClaim.ExpiresAt.Before(time.Now()) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid token",
			})
			return
		}

		if c.FullPath() == "/admin" && getClaim.Role != "admin" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "This route is only for admin",
			})
			return
		}
		c.Next()
	}
}

func userHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "welcome user",
	})
}

func adminHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "welcome admin",
	})
}

func main() {
	router := gin.Default()
	router.POST("/login", loginHandler)
	router.Use(authMiddleware())
	router.GET("/admin", adminHandler)
	router.GET("/user", userHandler)
	router.Run(":8080")
	// login
	// if valid generate new JWT
	// tokenString = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4iLCJlbWFpbCI6ImJlbmlAZXhhbXBsZS5jb20iLCJpc3MiOiJFZ25pZ21hQ2FtcCIsImV4cCI6MTcwNTMwMjAyOH0.6fHJZJDEMuFAkYoGBlwzPOxhOBMoFRxxy0aXfH6F8JM`
	// GET JWT
}
