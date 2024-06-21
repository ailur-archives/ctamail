package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
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

const saltChars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ23456789"

var (
	dbLocation = "/var/lib/maddy/credentials.db"
	conn       *sql.DB
)

func genSalt(length int) (string, error) {
	if length <= 0 {
		return "", errors.New("salt length must be greater than 0")
	}

	salt := make([]byte, length)
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	for i := range salt {
		salt[i] = saltChars[int(randomBytes[i])%len(saltChars)]
	}
	return string(salt), nil
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
		log.Fatalln("[FATAL] Error in config file at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
	}

	secretKey := viper.GetString("Config.secretkey")
	port := viper.GetString("Config.port")
	host := viper.GetString("Config.host")
	dbLocation = viper.GetString("Config.dblocation")
	var err error
	conn, err = sql.Open("sqlite3", dbLocation)
	if err != nil {
		log.Fatalln("[FATAL] Failed to open database at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
	}
	defer func(conn *sql.DB) {
		err := conn.Close()
		if err != nil {
			log.Fatalln("[FATAL] Failed to defer database connection in main() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
		}
	}(conn)

	if secretKey == "supersecretkey" {
		log.Println("[WARNING] Secret key not set. Please set the secret key to a non-default value.")
	}

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.LoadHTMLGlob("templates/*")
	router.Static("/static", "./static")
	store := cookie.NewStore([]byte(secretKey))
	router.Use(sessions.Sessions("currentSession", store))

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
		sessionId, err := genSalt(512)
		if err != nil {
			log.Println("[ERROR] Failed to generate session ID at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/ctamail and refer to the docs for more info. Your error code is: UNKNOWN-SIGNUP-SESSIONIDGEN")
			return
		}
		session.Options(sessions.Options{
			SameSite: 3,
		})
		data, err := captcha.New(500, 100)
		if err != nil {
			log.Println("[ERROR] Failed to generate captcha at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/ctamail and refer to the docs for more info. Your error code is: UNKNOWN-SIGNUP-CAPTCHAGEN")
			return
		}
		session.Set("captcha", data.Text)
		session.Set("id", sessionId)
		err = session.Save()
		if err != nil {
			log.Println("[ERROR] Failed to save session in /login at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/ctamail and refer to the docs for more info. Your error code is: UNKNOWN-SIGNUP-SESSIONSAVE")
			return
		}
		var b64bytes bytes.Buffer
		err = data.WriteImage(&b64bytes)
		if err != nil {
			log.Println("[ERROR] Failed to encode captcha at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/ctamail and refer to the docs for more info. Your error code is: UNKNOWN-SIGNUP-CAPTCHAENCODE")
			return
		}
		c.HTML(200, "signup.html", gin.H{
			"captcha_image": base64.StdEncoding.EncodeToString(b64bytes.Bytes()),
			"unique_token":  sessionId,
		})
	})

	router.GET("/account", func(c *gin.Context) {
		loggedIn, err := c.Cookie("loggedIn")
		if errors.Is(err, http.ErrNoCookie) || loggedIn != "true" {
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
			log.Println("[ERROR] Failed to save session in /api/signup at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/ctamail and refer to the docs for more info. Your error code is: UNKNOWN-API-SIGNUP-SESSIONSAVE")
			return
		}

		hashedPassword, err := computeBcrypt(10, data["password"].(string))
		if err != nil {
			log.Println("[ERROR] Failed to hash password in /api/signup at", time.Now().Unix(), err)
			c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/ctamail and refer to the docs for more info. Your error code is: UNKNOWN-API-SIGNUP-PASSHASH")
			return
		}

		_, err = conn.Exec("INSERT INTO passwords (key, value) VALUES (?, ?)", data["username"].(string), hashedPassword)
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

		var rows string
		err = conn.QueryRow("SELECT value FROM passwords WHERE key = ?", data["username"].(string)).Scan(&rows)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.String(401, "Invalid username")
				return
			} else {
				log.Println("[ERROR] Failed to query database in /api/login at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/ctamail and refer to the docs for more info. Your error code is: UNKNOWN-API-LOGIN-DBQUERY")
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

		result, err := conn.Exec("DELETE FROM passwords WHERE key = ? AND value = ?", data["username"].(string), data["password"].(string))
		if err != nil {
			log.Println("[ERROR] Failed to query database in /api/deleteacct at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/ctamail and refer to the docs for more info. Your error code is: UNKNOWN-API-DELETEACCT-DBQUERY")
		} else {
			rowsAffected, err := result.RowsAffected()
			if err != nil {
				log.Println("[ERROR] Failed to get rows affected in /api/deleteacct at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/ctamail and refer to the docs for more info. Your error code is: UNKNOWN-API-DELETEACCT-ROWSAFFECTED")
			} else {
				if rowsAffected == int64(0) {
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

		newHash, err := computeBcrypt(10, data["newpass"].(string))
		if err != nil {
			log.Println("[ERROR] Failed to hash password in /api/changepass at", time.Now().Unix(), err)
			c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/ctamail and refer to the docs for more info. Your error code is: UNKNOWN-API-CHANGEPASS-PASSHASH")
			return
		}

		result, err := conn.Exec("UPDATE passwords SET value = ? WHERE key = ? AND value = ?", newHash, data["username"].(string), data["password"].(string))
		if err != nil {
			log.Println("[ERROR] Failed to query database in /api/changepass at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/ctamail and refer to the docs for more info. Your error code is: UNKNOWN-API-CHANGEPASS-DBQUERY")
		} else {
			rowsAffected, err := result.RowsAffected()
			if err != nil {
				log.Println("[ERROR] Failed to get rows affected in /api/changepass at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.String(500, "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/ctamail and refer to the docs for more info. Your error code is: UNKNOWN-API-CHANGEPASS-ROWSAFFECTED")
			} else {
				if rowsAffected == int64(0) {
					c.String(401, "Invalid username or password")
				} else {
					c.JSON(200, gin.H{"password": newHash})
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

	log.Println("[INFO] Server started at", time.Now().Unix())
	log.Println("[INFO] Welcome to CTAMail! Today we are running on IP " + host + " on port " + port + ".")
	err = router.Run(host + ":" + port)
	if err != nil {
		log.Fatalln("[FATAL] Server failed begin operations at", time.Now().Unix(), err)
	}
}
