package main

import (
"fmt"
"time"
"github.com/sirupsen/logrus"
"github.com/google/uuid"
"github.com/spf13/viper"
"github.com/gin-gonic/gin"
)

func main() {
	fmt.Println("Starting Go App...")
	// 3. Viper
	viper.SetDefault("ContentDir", "content")

	// 4. Gin (Web Server)
	go func() {
		r := gin.Default()
		r.GET("/", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"message": "pong",
				"uuid":    uuid.New().String(),
			})
		})
		r.Run(":8080")
	}()

	for {
		// 1. Logrus
		logrus.Info("Hello World from Go!")

		// 2. UUID
		id := uuid.New()
		logrus.Infof("Generated UUID: %s", id.String())

		logrus.Infof("Viper Config: %s", viper.GetString("ContentDir"))

		time.Sleep(5 * time.Second)
	}
}
