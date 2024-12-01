package main

import (
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// DB Models
// Participant represents the participant table
type Participant struct {
	ID   uint   `gorm:"primaryKey;column:id;type:INTEGER;not null" json:"id"`
	Name string `gorm:"column:name;type:VARCHAR(50);not null" json:"name"`
}

// TableName returns the table name of the Participant model
func (Participant) TableName() string {
	return "participant"
}

// Event represents the event table
type Event struct {
	ID   uint   `gorm:"primaryKey;column:id;type:INTEGER;not null" json:"id"`
	Name string `gorm:"column:name;type:VARCHAR(100);not null" json:"name"`
	Date string `gorm:"column:date;type:VARCHAR(10);not null" json:"date"` // 유지: VARCHAR(10)
}

// TableName returns the table name of the Event model
func (Event) TableName() string {
	return "event"
}

// Response represents the response table
type Response struct {
	ID            uint   `gorm:"primaryKey;column:id;type:INTEGER;not null" json:"id"`
	ParticipantID uint   `gorm:"column:participant_id;type:INTEGER;not null" json:"participantId"`
	EventID       uint   `gorm:"column:event_id;type:INTEGER;not null" json:"eventId"`
	Status        string `gorm:"column:status;type:CHAR(1);not null" json:"status"` // O, X, ?
}

// TableName returns the table name of the Response model
func (Response) TableName() string {
	return "response"
}

// Comment represents the comment table
type Comment struct {
	ID            uint   `gorm:"primaryKey;column:id;type:INTEGER;not null" json:"id"`
	ParticipantID uint   `gorm:"column:participant_id;type:INTEGER;not null" json:"participantId"`
	Text          string `gorm:"column:text;type:TEXT;not null" json:"text"`
}

// TableName returns the table name of the Comment model
func (Comment) TableName() string {
	return "comment"
}

// JWT Secret Key
var jwtSecret = []byte(os.Getenv("JWT_SECRET_KEY"))

// Database Initialization
var db *gorm.DB

func initDB() {
	var err error
	db, err = gorm.Open(sqlite.Open("./instance/app.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	db.AutoMigrate(&Participant{}, &Event{}, &Response{}, &Comment{})
}

// Helper Functions
func generatePasswordHash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPasswordHash(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func createJWT() (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "admin",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	signedToken, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}
	log.Println("Generated JWT:", signedToken) // 토큰 로그 출력
	return signedToken, nil
}

func parseJWT(authorizationHeader string) error {
	// Authorization 헤더에서 "Bearer " 제거
	if !strings.HasPrefix(authorizationHeader, "Bearer ") {
		return errors.New("Authorization header does not contain Bearer token")
	}
	tokenStr := strings.TrimPrefix(authorizationHeader, "Bearer ")

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return jwtSecret, nil
	})
	if err != nil {
		log.Println("JWT parsing error:", err) // 오류 로그 출력
		return errors.New("unauthorized")
	}

	// 토큰 검증
	if !token.Valid {
		log.Println("Invalid JWT token") // 잘못된 토큰 오류 로그
		return errors.New("unauthorized")
	}

	log.Println("JWT token valid") // 유효한 토큰 로그 출력
	return nil
}

// Middleware
func jwtMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		if err := parseJWT(token); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// Handlers
func login(c *gin.Context) {
	var request struct {
		Password string `json:"password"`
	}

	if err := c.BindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	adminPassword := os.Getenv("ADMIN_PASSWORD")
	if adminPassword == "" {
		adminPassword = "1q2w3e4r!" // Not used in production
	}
	adminHash, _ := generatePasswordHash(adminPassword)

	if !checkPasswordHash(adminHash, request.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Bad password"})
		return
	}

	token, err := createJWT()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"sessionKey": token})
}

func getParticipants(c *gin.Context) {
	var participants []Participant
	db.Find(&participants)
	c.JSON(http.StatusOK, participants)

}

func createParticipant(c *gin.Context) {
	var request struct {
		Name string `json:"name"`
	}

	if err := c.BindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	participant := Participant{Name: request.Name}
	db.Create(&participant)
	//check
	c.JSON(http.StatusCreated, participant)

}

func deleteParticipant(c *gin.Context) {
	id := c.Param("id")
	var participant Participant

	if err := db.First(&participant, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Participant not found"})
		return
	}

	db.Delete(&participant)
	db.Where("participant_id = ?", id).Delete(&Comment{})
	db.Where("participant_id = ?", id).Delete(&Response{})
	c.JSON(http.StatusOK, gin.H{"message": "Participant deleted"})
}

func getEvents(c *gin.Context) {
	var events []Event
	db.Find(&events)
	c.JSON(http.StatusOK, events)
}

func createEvent(c *gin.Context) {
	var request struct {
		Name string `json:"name"`
		Date string `json:"date"`
	}

	if err := c.BindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	event := Event{Name: request.Name, Date: request.Date}
	db.Create(&event)
	c.JSON(http.StatusCreated, event)
}

func updateEvent(c *gin.Context) {
	id := c.Param("id")
	var event Event

	if err := db.First(&event, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Event not found"})
		return
	}

	var request struct {
		Name string `json:"name"`
		Date string `json:"date"`
	}
	if err := c.BindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	event.Name = request.Name
	event.Date = request.Date
	db.Save(&event)
	c.JSON(http.StatusOK, event)
}

func deleteEvent(c *gin.Context) {
	id := c.Param("id")
	var event Event

	if err := db.First(&event, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Event not found"})
		return
	}

	db.Where("event_id = ?", id).Delete(&Response{})
	db.Delete(&event)
	c.JSON(http.StatusOK, gin.H{"message": "Event deleted"})
}

func getComments(c *gin.Context) {
	var comments []Comment
	db.Find(&comments)
	c.JSON(http.StatusOK, comments)
}

func createComment(c *gin.Context) {
	var request struct {
		ParticipantID uint   `json:"participantId"`
		Text          string `json:"text"`
	}

	if err := c.BindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	comment := Comment{ParticipantID: request.ParticipantID, Text: request.Text}
	db.Create(&comment)
	c.JSON(http.StatusCreated, comment)
}

// Response Handlers
func getResponses(c *gin.Context) {
	var responses []Response
	db.Find(&responses)
	c.JSON(http.StatusOK, responses)
}

func createResponse(c *gin.Context) {
	var request struct {
		Responses []struct {
			ParticipantID uint   `json:"participantId"`
			EventID       uint   `json:"eventId"`
			Status        string `json:"status"`
		} `json:"responses"`
	}

	if err := c.BindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	var savedResponses []Response
	for _, res := range request.Responses {
		var response Response
		if err := db.Where("participant_id = ? AND event_id = ?", res.ParticipantID, res.EventID).First(&response).Error; err != nil {
			response = Response{
				ParticipantID: res.ParticipantID,
				EventID:       res.EventID,
				Status:        res.Status,
			}
			db.Create(&response)
		} else {
			response.Status = res.Status
			db.Save(&response)
		}
		savedResponses = append(savedResponses, response)
	}

	c.JSON(http.StatusOK, savedResponses)
}

func cleanUpInvalidReferences() {
	// Remove comments with invalid participant IDs
	db.Exec("DELETE FROM comments WHERE participant_id NOT IN (SELECT id FROM participants)")

	// Remove responses with invalid participant or event IDs
	db.Exec("DELETE FROM responses WHERE participant_id NOT IN (SELECT id FROM participants)")
	db.Exec("DELETE FROM responses WHERE event_id NOT IN (SELECT id FROM events)")
}

// Main Function
func main() {
	initDB()
	//defer db.Close()

	cleanUpInvalidReferences()

	r := gin.Default()

	r.POST("/api/login", login)

	auth := r.Group("/api", jwtMiddleware())
	auth.GET("/participants", getParticipants)
	auth.POST("/participants", createParticipant)
	auth.DELETE("/participants/:id", deleteParticipant)

	auth.GET("/events", getEvents)
	auth.POST("/events", createEvent)
	auth.PUT("/events/:id", updateEvent)
	auth.DELETE("/events/:id", deleteEvent)

	auth.GET("/comments", getComments)
	auth.POST("/comments", createComment)

	auth.GET("/responses", getResponses)
	auth.POST("/responses", createResponse)

	if err := r.Run(":5000"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
