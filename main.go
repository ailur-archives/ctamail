package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"time"

	"centrifuge.hectabit.org/HectaBit/captcha"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

const salt_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var DBLOCATION = "/var/lib/maddy/credentials.db"

func get_db_connection() *sql.DB {
	db, _ := sql.Open("sqlite3", DBLOCATION)
	return db
}

func genSalt(length int) string {
	if length <= 0 {
		fmt.Println("[ERROR] Known in genSalt() at", strconv.FormatInt(time.Now().Unix(), 10)+":", "Salt length must be at least one.")
	}

	salt := make([]byte, length)
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		fmt.Println("[ERROR] Unknown in genSalt() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
	}

	for i := range salt {
		salt[i] = salt_chars[int(randomBytes[i])%len(salt_chars)]
	}
	return string(salt)
}

func computeBcrypt(cost int, pass string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func verifyBcrypt(pass, hashSalt string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashSalt), []byte(pass))
}

func main() {
	viper.SetConfigName("config")
	viper.AddConfigPath("./")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		fmt.Println("[FATAL] Error in config file at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
		os.Exit(1)
	}

	SECRET_KEY := viper.GetString("Config.secretkey")
	PORT := viper.GetString("Config.port")
	HOST := viper.GetString("Config.host")
	DBLOCATION = viper.GetString("Config.dblocation")

	if SECRET_KEY == "supersecretkey" {
		fmt.Println("[WARNING] Secret key not set. Please set the secret key to a non-default value.")
	}

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.LoadHTMLGlob("templates/*")
	router.Static("/static", "./static")
	store := cookie.NewStore([]byte(SECRET_KEY))
	router.Use(sessions.Sessions("currentsession", store))

	// Enable CORS
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "*")

		// Handle preflight requests
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(200)
			return
		}

		c.Next()
	})

	router.GET("/login", func(c *gin.Context) {
		session := sessions.Default(c)
		sessionid := genSalt(512)
		session.Options(sessions.Options{
			SameSite: 3,
		})
		data, err := captcha.New(500, 100)
		if err != nil {
			fmt.Println("[ERROR] Failed to generate captcha at", time.Now().Unix(), err)
			c.String(500, "Failed to generate captcha")
			return
		}
		session.Set("captcha", data.Text)
		session.Set("id", sessionid)
		err = session.Save()
		if err != nil {
			fmt.Println("[ERROR] Failed to save session in /login at", time.Now().Unix(), err)
			c.String(500, "Failed to save session")
			return
		}
		var b64bytes bytes.Buffer
		err = data.WriteImage(&b64bytes)
		if err != nil {
			fmt.Println("[ERROR] Failed to encode captcha at", time.Now().Unix(), err)
			c.String(500, "Failed to encode captcha")
			return
		}
		c.HTML(200, "main.html", gin.H{
			"captcha_image": base64.StdEncoding.EncodeToString(b64bytes.Bytes()),
			"unique_token":  sessionid,
		})
	})

	router.POST("/api/signup", func(c *gin.Context) {
		err := c.Request.ParseForm()
		if err != nil {
			c.String(400, "Failed to parse form")
			return
		}
		data := c.Request.Form
		session := sessions.Default(c)

		if data.Get("captcha") != session.Get("captcha") {
			c.HTML(200, "badcaptcha.html", gin.H{})
			return
		}

		if data.Get("unique_token") != session.Get("id") {
			c.HTML(200, "badtoken.html", gin.H{})
			return
		}

		session.Delete("captcha")
		session.Delete("id")

		err = session.Save()
		if err != nil {
			fmt.Println("[ERROR] Failed to save session in /api/signup at", time.Now().Unix(), err)
			c.String(500, "Failed to save session")
			return
		}

		conn := get_db_connection()
		defer func(conn *sql.DB) {
			err := conn.Close()
			if err != nil {
				fmt.Println("[ERROR] Failed to defer database connection at", time.Now().Unix(), err)
				c.String(500, "Failed to defer database connection")
				return
			}
		}(conn)

		hashedpass, err := computeBcrypt(10, data.Get("password"))
		if err != nil {
			fmt.Println("[ERROR] Failed to hash password connection at", time.Now().Unix(), err)
			c.String(500, "Failed to hash password")
			return
		}

		_, err = conn.Exec("INSERT INTO passwords (key, value) VALUES (?, ?)", data.Get("username"), hashedpass)
		if err != nil {
			c.HTML(500, "taken.html", gin.H{})
			return
		}

		c.HTML(200, "postsignup.html", gin.H{})
	})

	fmt.Println("[INFO] Server started at", time.Now().Unix())
	fmt.Println("[INFO] Welcome to CTAMail! Today we are running on IP " + HOST + " on port " + PORT + ".")
	err := router.Run(HOST + ":" + PORT)
	if err != nil {
		fmt.Println("[FATAL] Server failed to start at", time.Now().Unix(), err)
		return
	}
}
