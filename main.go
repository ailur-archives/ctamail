package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"centrifuge.hectabit.org/HectaBit/captcha"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

const salt_chars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ23456789"

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
	return "bcrypt:" + string(hash), nil
}

func verifyBcrypt(hash, pass string) error {
	return bcrypt.CompareHashAndPassword([]byte(strings.TrimPrefix(hash, "bcrypt:")), []byte(pass))
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

	router.GET("/signup", func(c *gin.Context) {
		session := sessions.Default(c)
		sessionid := genSalt(512)
		session.Options(sessions.Options{
			SameSite: 3,
		})
		data, err := captcha.New(500, 100)
		if err != nil {
			fmt.Println("[ERROR] Failed to generate captcha at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.String(500, "Failed to generate captcha")
			return
		}
		session.Set("captcha", data.Text)
		session.Set("id", sessionid)
		err = session.Save()
		if err != nil {
			fmt.Println("[ERROR] Failed to save session in /login at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.String(500, "Failed to save session")
			return
		}
		var b64bytes bytes.Buffer
		err = data.WriteImage(&b64bytes)
		if err != nil {
			fmt.Println("[ERROR] Failed to encode captcha at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.String(500, "Failed to encode captcha")
			return
		}
		c.HTML(200, "signup.html", gin.H{
			"captcha_image": base64.StdEncoding.EncodeToString(b64bytes.Bytes()),
			"unique_token":  sessionid,
		})
	})

	router.GET("/account", func(c *gin.Context) {
		loggedin, err := c.Cookie("loggedin")
		if errors.Is(err, http.ErrNoCookie) || loggedin != "true" {
			c.HTML(200, "login.html", gin.H{})
			return
		} else {
			c.HTML(200, "dashboard.html", gin.H{})
		}
	})

	router.POST("/api/signup", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		session := sessions.Default(c)

		if data["unique_token"].(string) != session.Get("id") {
			c.HTML(403, "badtoken.html", gin.H{})
			return
		}

		if data["captcha"].(string) != session.Get("captcha") {
			c.HTML(400, "badcaptcha.html", gin.H{})
			return
		}

		if !regexp.MustCompile(`^[a-zA-Z0-9.]+$`).MatchString(data["username"].(string)) {
			c.String(402, "Invalid username")
			return
		}

		session.Delete("captcha")
		session.Delete("id")

		err = session.Save()
		if err != nil {
			fmt.Println("[ERROR] Failed to save session in /api/signup at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.String(500, "Failed to save session")
			return
		}

		conn := get_db_connection()
		defer func(conn *sql.DB) {
			err := conn.Close()
			if err != nil {
				fmt.Println("[ERROR] Failed to defer database connection in /api/signup at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.String(500, "Failed to defer database connection")
				return
			}
		}(conn)

		hashedpass, err := computeBcrypt(10, data["password"].(string))
		if err != nil {
			fmt.Println("[ERROR] Failed to hash password in /api/signup at", time.Now().Unix(), err)
			c.String(500, "Failed to hash password")
			return
		}

		_, err = conn.Exec("INSERT INTO passwords (key, value) VALUES (?, ?)", data["username"].(string), hashedpass)
		if err != nil {
			c.String(501, "Username taken")
			return
		}

		c.String(200, "Success")
	})

	router.POST("/api/login", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		conn := get_db_connection()
		defer func(conn *sql.DB) {
			err := conn.Close()
			if err != nil {
				fmt.Println("[ERROR] Failed to defer database connection at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.String(500, "Failed to defer database connection")
				return
			}
		}(conn)

		var rows string
		err = conn.QueryRow("SELECT value FROM passwords WHERE key = ?", data["username"].(string)).Scan(&rows)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.String(401, "Invalid username")
				return
			} else {
				fmt.Println("[ERROR] Failed to query database in /api/login at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.String(500, "Failed to query database")
				return
			}
		}

		err = verifyBcrypt(rows, data["password"].(string))
		if err != nil {
			c.String(403, "Password is incorrect")
			return
		}

		c.JSON(200, gin.H{"password": rows})
	})

	router.POST("/api/deleteacct", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		conn := get_db_connection()
		defer func(conn *sql.DB) {
			err := conn.Close()
			if err != nil {
				fmt.Println("[ERROR] Failed to defer database connection in /api/deleteacct at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.String(500, "Failed to defer database connection")
				return
			}
		}(conn)

		result, err := conn.Exec("DELETE FROM passwords WHERE key = ? AND value = ?", data["username"].(string), data["password"].(string))
		if err != nil {
			fmt.Println("[ERROR] Failed to query database in /api/deleteacct at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.String(500, "Failed to query database")
		} else {
			rowsaffected, err := result.RowsAffected()
			if err != nil {
				fmt.Println("[ERROR] Failed to get rows affected in /api/deleteacct at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.String(500, "Failed to get rows affected")
			} else {
				if rowsaffected == int64(0) {
					c.String(401, "Invalid username or password")
				} else {
					c.String(200, "Success")
				}
			}
		}
	})

	router.POST("/api/changepass", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		conn := get_db_connection()
		defer func(conn *sql.DB) {
			err := conn.Close()
			if err != nil {
				fmt.Println("[ERROR] Failed to defer database connection in /api/changepass at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.String(500, "Failed to defer database connection")
				return
			}
		}(conn)

		newhash, err := computeBcrypt(10, data["newpass"].(string))
		if err != nil {
			fmt.Println("[ERROR] Failed to hash password in /api/changepass at", time.Now().Unix(), err)
			c.String(500, "Failed to hash password")
			return
		}

		result, err := conn.Exec("UPDATE passwords SET value = ? WHERE key = ? AND value = ?", newhash, data["username"].(string), data["password"].(string))
		if err != nil {
			fmt.Println("[ERROR] Failed to query database in /api/changepass at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.String(500, "Failed to query database")
		} else {
			rowsaffected, err := result.RowsAffected()
			if err != nil {
				fmt.Println("[ERROR] Failed to get rows affected in /api/changepass at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.String(500, "Failed to get rows affected")
			} else {
				if rowsaffected == int64(0) {
					c.String(401, "Invalid username or password")
				} else {
					c.JSON(200, gin.H{"password": newhash})
				}
			}
		}
	})

	router.GET("/account/logout", func(c *gin.Context) {
		c.HTML(200, "logout.html", gin.H{})
	})

	router.GET("/account/deleteacct", func(c *gin.Context) {
		c.HTML(200, "deleteacct.html", gin.H{})
	})

	router.GET("/account/changepass", func(c *gin.Context) {
		c.HTML(200, "changepass.html", gin.H{})
	})

	router.GET("/usererror", func(c *gin.Context) {
		c.HTML(200, "usererror.html", gin.H{})
	})

	router.GET("/accounterror", func(c *gin.Context) {
		c.HTML(200, "accounterror.html", gin.H{})
	})

	router.GET("/badcaptcha", func(c *gin.Context) {
		c.HTML(200, "badcaptcha.html", gin.H{})
	})

	router.GET("/signuperror", func(c *gin.Context) {
		c.HTML(200, "signuperror.html", gin.H{})
	})

	router.GET("/loginerror", func(c *gin.Context) {
		c.HTML(200, "loginerror.html", gin.H{})
	})

	router.GET("/invalidtoken", func(c *gin.Context) {
		c.HTML(200, "invalidtoken.html", gin.H{})
	})

	router.GET("/invaliduser", func(c *gin.Context) {
		c.HTML(200, "invaliduser.html", gin.H{})
	})

	router.GET("/badpassword", func(c *gin.Context) {
		c.HTML(200, "badpassword.html", gin.H{})
	})

	router.GET("/baduser", func(c *gin.Context) {
		c.HTML(200, "baduser.html", gin.H{})
	})

	router.GET("/success", func(c *gin.Context) {
		c.HTML(200, "success.html", gin.H{})
	})

	router.GET("/taken", func(c *gin.Context) {
		c.HTML(200, "taken.html", gin.H{})
	})

	router.GET("/", func(c *gin.Context) {
		c.HTML(200, "index.html", gin.H{})
	})

	router.GET("/cta", func(c *gin.Context) {
		c.HTML(200, "cta.html", gin.H{})
	})

	fmt.Println("[INFO] Server started at", time.Now().Unix())
	fmt.Println("[INFO] Welcome to CTAMail! Today we are running on IP " + HOST + " on port " + PORT + ".")
	err := router.Run(HOST + ":" + PORT)
	if err != nil {
		fmt.Println("[FATAL] Server failed to start at", time.Now().Unix(), err)
		return
	}
}
