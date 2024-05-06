package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
)

var CHALL_URL string = os.Getenv("CHALL_URL")
var FLAG string = os.Getenv("FLAG")
var HEADLESS_HOST string = os.Getenv("HEADLESS_HOST")
var HEADLESS_AUTH string = os.Getenv("HEADLESS_AUTH")

const DIM = 7

var db *sql.DB
var sessionStore *sessions.CookieStore

func main() {

	// Initialize db
	var err error
	db, err = sql.Open("sqlite3", "/data/db.sqlite")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	err = initializeDB()
	if err != nil {
		log.Fatal("Error initializing database: ", err)
	}

	// Initialize sessions
	// generate a random key
	key := make([]byte, 32)

	_, err = rand.Read(key)
	if err != nil {
		log.Fatal(err)
	}

	sessionStore = sessions.NewCookieStore(key)

	// Create a new router
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(securityHeadersMiddleware)
	r.Use(redirectMiddleware)

	// Define your routes
	r.Get("/", homeHandler)
	r.Get("/register", registerHandler)
	r.Get("/login", loginGetHandler)
	r.Post("/login", loginPostHandler)
	r.Get("/board", authMiddleware(boardHandler))
	r.Get("/newboard", authMiddleware(newBoardHandler))
	r.Get("/checkwin", authMiddleware(checkWinHandler))
	r.Get("/clone", authMiddleware(cloneBoardHandler))
	r.Post("/checkboard", authMiddleware(checkBoardHandler))
	r.Post("/guess", authMiddleware(submitGuessHandler))

	// Start the server
	fmt.Println("Server started on http://localhost:8000")
	log.Fatal(http.ListenAndServe(":8000", r))
}

func initializeDB() error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id VARCHAR(32) PRIMARY KEY,
		admin BOOLEAN NOT NULL DEFAULT 0,
		points INTEGER NOT NULL DEFAULT 0,
		tries INTEGER NOT NULL DEFAULT 0,
		board TEXT NOT NULL DEFAULT "",
		explored_board TEXT NOT NULL DEFAULT "",
		times_cloned INTEGER NOT NULL DEFAULT 0
	);
	`)
	if err != nil {
		return err
	}

	return nil
}

func getUserAndBoards(r *http.Request) (userid string, board []int, exploredBoard []int, err error) {
	// Get the user id from the session
	s, err := sessionStore.Get(r, "session")
	if err != nil {
		return "", nil, nil, err
	}

	userid, _ = s.Values["userid"].(string)

	// Get the board from the database
	var boardJson string
	var explBoardJson string
	row := db.QueryRow("SELECT board, explored_board FROM users WHERE id = ?", userid)
	err = row.Scan(&boardJson, &explBoardJson)

	if err != nil {
		return "", nil, nil, err
	}

	// fmt.Println("UserID: ", userid)
	// fmt.Println("Board: ", boardJson)
	// fmt.Println("Explored Board: ", explBoardJson)

	// Decode the board
	board = DecodeBoard(boardJson)
	exploredBoard = DecodeBoard(explBoardJson)

	return userid, board, exploredBoard, nil
}

func getUserAndPoints(r *http.Request) (userid string, points int, tries int, err error) {
	// Get the user id from the session
	s, err := sessionStore.Get(r, "session")
	if err != nil {
		return "", 0, 0, err
	}

	if s.Values["userid"] == nil {
		return "", 0, 0, nil
	}

	userid, _ = s.Values["userid"].(string)

	row := db.QueryRow("SELECT points, tries FROM users WHERE id = ?", userid)
	row.Scan(&points, &tries)

	return userid, points, tries, nil
}

func renderTemplate(w http.ResponseWriter, templateFile string, data interface{}) {
	// Parse the template file
	tmpl, err := template.New(templateFile).Funcs(template.FuncMap{"mod": func(i, j int) int { return i % j }}).ParseFiles("templates/"+templateFile, "templates/header.html")
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Execute the template with the data
	err = tmpl.Execute(w, data)
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set security headers
		// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "0")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		// I have some inline scripts in the templates, who cares about CSP anyway
		// w.Header().Set("Content-Security-Policy", "script-src 'self';")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-site")
		w.Header().Set("Permissions-Policy", "geolocation=(), camera=(), microphone=()")

		next.ServeHTTP(w, r)
	})
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, err := sessionStore.Get(r, "session")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Check if user is authenticated
		if _, ok := s.Values["userid"].(string); !ok {
			// Redirect to login
			http.Redirect(w, r, "/login?redirect="+r.URL.Path, http.StatusFound)
			return
		}

		// Call the next handler
		next.ServeHTTP(w, r)
	}
}

func redirectMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlto := r.URL.Query().Get("redirect")
		if urlto != "" {
			// check if the user is authenticated
			s, err := sessionStore.Get(r, "session")
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			userid, ok := s.Values["userid"].(string)

			if !ok || userid == "" {
				next.ServeHTTP(w, r)
				return
			}

			a, err := url.Parse(urlto)

			if err == nil {
				// accept only http and https or relative url
				if a.Scheme != "" && a.Scheme != "http" && a.Scheme != "https" {
					http.Error(w, "URL parameter is invalid", http.StatusBadRequest)
					return
				}

				fmt.Println("Scheme: ", a.Scheme)
				fmt.Println("Host: ", a.Host)
				fmt.Println("HOST CHALL: ", r.Host)

				// only accept same host
				if a.Scheme != "" && a.Host != r.Host {
					http.Error(w, "URL parameter is invalid", http.StatusBadRequest)
					return
				}
			}

			if err != nil {
				log.Println(err)
			}

			http.Redirect(w, r, urlto, http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	userid, points, tries, err := getUserAndPoints(r)

	if err != nil {
		log.Println(err)
		// Clear session cookie
		s, _ := sessionStore.Get(r, "session")
		s.Options.MaxAge = -1
		s.Save(r, w)

		http.Error(w, "Something is wrong, please retry", http.StatusInternalServerError)
		return
	}

	flag := ""
	if points >= 20 && points == tries {
		suffix := make([]byte, 4)
		_, _ = rand.Read(suffix)
		flag = FLAG[:len(FLAG)-1] + "_" + hex.EncodeToString(suffix) + "}"
	}

	data := struct {
		Userid string
		Points int
		Tries  int
		Flag   string
	}{
		Userid: userid,
		Points: points,
		Tries:  tries,
		Flag:   flag,
	}

	renderTemplate(w, "home.html", data)
}

func boardHandler(w http.ResponseWriter, r *http.Request) {
	// Get the user id from the session
	s, err := sessionStore.Get(r, "session")
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	userid, _ := s.Values["userid"].(string)

	// Get user info
	var admin bool
	var boardJson string
	var explBoardJson string
	row := db.QueryRow("SELECT admin, board, explored_board FROM users WHERE id = ?", userid)
	err = row.Scan(&admin, &boardJson, &explBoardJson)

	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if boardJson == "" {
		http.Redirect(w, r, "/newboard", http.StatusFound)
		return
	}

	board := DecodeBoard(explBoardJson)

	if admin {
		xray := r.URL.Query().Get("xray")
		if xray == "1" {
			board = DecodeBoard(boardJson)
		}
	}

	data := struct {
		Board []int
	}{
		Board: board,
	}

	renderTemplate(w, "board.html", data)
}

func submitGuessHandler(w http.ResponseWriter, r *http.Request) {
	userid, board, exploredBoard, err := getUserAndBoards(r)
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Parse the form
	err = r.ParseForm()
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Get the guess from the form
	x := r.PostFormValue("guess")
	guess, err := strconv.Atoi(x)

	if err != nil {
		log.Println(err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Check if the guess is a bomb
	if board[guess] == 100 {
		// Update points and delete the board
		_, err := db.Exec(`UPDATE users SET tries = tries + 1, board = "", explored_board = "" WHERE id = ?;`, userid)

		if err != nil {
			log.Println(err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "100")
		return
	} else {
		exploredBoard[guess] = board[guess]

		_, err := db.Exec(`UPDATE users SET explored_board = ? WHERE id = ? AND board <> "";`, EncodeBoard(exploredBoard), userid)

		if err != nil {
			log.Println(err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		fmt.Fprint(w, strconv.Itoa(exploredBoard[guess]))
	}

}

func checkWinHandler(w http.ResponseWriter, r *http.Request) {
	userid, board, exploredBoard, err := getUserAndBoards(r)

	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if len(board) == DIM*DIM {
		win := true
		for i := 0; i < DIM*DIM; i++ {
			if exploredBoard[i] == -1 && board[i] != 100 {
				win = false
				break
			}
		}

		if win {
			_, err := db.Exec(`UPDATE users SET points = points + 1, tries = tries + 1, board = "" WHERE id = ? AND board <> "";`, userid)

			if err != nil {
				log.Println(err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
		}

		fmt.Fprint(w, strconv.FormatBool(win))
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	s, err := sessionStore.Get(r, "session")
	if err != nil {
		log.Println(err)

		// remove session cookie
		s.Options.MaxAge = 0
		s.Save(r, w)

		http.Error(w, "Something is wrong with your session, refresh the page", http.StatusBadRequest)
		return
	}

	// Check if the user is already authenticated
	if s.Values["userid"] != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Create new user
	// Generate a random id
	id := make([]byte, 16)
	_, err = rand.Read(id)
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	userid := fmt.Sprintf("%x", id)

	// Generate the board
	board := GenerateBoard()
	exploredBoard := GenerateExploredBoard()

	// Insert the board into the database
	_, err = db.Exec("INSERT INTO users (id, board, explored_board) VALUES ( ? , ? , ? );", userid, EncodeBoard(board), EncodeBoard(exploredBoard))
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Set the user id in the session
	s.Values["userid"] = userid
	err = s.Save(r, w)
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	renderTemplate(w, "register.html", userid)
}

func loginGetHandler(w http.ResponseWriter, r *http.Request) {
	// Get the user id from the session
	s, err := sessionStore.Get(r, "session")
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Check if the user is already authenticated
	if s.Values["userid"] != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	renderTemplate(w, "login.html", nil)
}

func loginPostHandler(w http.ResponseWriter, r *http.Request) {
	// Get the user id from the session
	s, err := sessionStore.Get(r, "session")
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Check if the user is already authenticated
	if s.Values["userid"] != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Parse the form
	err = r.ParseForm()
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Get the user id from the form
	userid := r.PostFormValue("userid")

	// Check if the user exists
	var count int
	row := db.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", userid)
	row.Scan(&count)

	if count == 0 {
		data := struct {
			Error string
		}{
			Error: "User does not exist",
		}
		renderTemplate(w, "login.html", data)

		return
	}

	// Set the user id in the session
	s.Values["userid"] = userid
	err = s.Save(r, w)
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func newBoardHandler(w http.ResponseWriter, r *http.Request) {
	// Get the user id from the session
	s, err := sessionStore.Get(r, "session")
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	userid, _ := s.Values["userid"].(string)

	// Generate the boards
	board := GenerateBoard()
	exploredBoard := GenerateExploredBoard()

	// Insert the board into the database
	_, err = db.Exec("UPDATE users SET board = ?, explored_board = ?, times_cloned = 0 WHERE id = ?", EncodeBoard(board), EncodeBoard(exploredBoard), userid)
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/board", http.StatusFound)
}

func cloneBoardHandler(w http.ResponseWriter, r *http.Request) {
	// Get the user id from the session
	s, err := sessionStore.Get(r, "session")
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	userid, _ := s.Values["userid"].(string)

	// Check if there's a GET paramenter for the userid to clone
	cloneUserid := r.URL.Query().Get("cloneid")

	if cloneUserid == "" {
		renderTemplate(w, "clone.html", nil)
		return
	}

	var admin bool

	row := db.QueryRow("SELECT admin FROM users WHERE id = ?", userid)
	row.Scan(&admin)

	if !admin {
		data := struct {
			Error   string
			Success bool
		}{
			Error:   "Only admin users can clone a board",
			Success: false,
		}
		renderTemplate(w, "clone.html", data)
		return
	}

	// Get the board from the database
	var boardJson string
	var timesCloned int
	row = db.QueryRow("SELECT board, times_cloned FROM users WHERE id = ?", cloneUserid)
	row.Scan(&boardJson, &timesCloned)

	if boardJson == "" {
		data := struct {
			Error   string
			Success bool
		}{
			Error:   "User does not exist",
			Success: false,
		}
		renderTemplate(w, "clone.html", data)
		return
	}

	if timesCloned >= 5 {
		data := struct {
			Error   string
			Success bool
		}{
			Error:   "Board has been cloned too many times",
			Success: false,
		}
		renderTemplate(w, "clone.html", data)
		return
	}

	log.Printf("Cloning board from %s to %s", cloneUserid, userid)

	_, err = db.Exec("UPDATE users SET times_cloned = times_cloned + 1 WHERE id = ?", cloneUserid)
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	exploredBoard := GenerateExploredBoard()

	// Insert the board into the database
	_, err = db.Exec("UPDATE users SET board = ?, explored_board = ? WHERE id = ?", boardJson, EncodeBoard(exploredBoard), userid)
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Success bool
		Error   string
	}{
		Success: true,
		Error:   "",
	}

	renderTemplate(w, "clone.html", data)
}

func checkBoardHandler(w http.ResponseWriter, r *http.Request) {
	// Create a new user for the bot
	id := make([]byte, 16)
	_, err := rand.Read(id)
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	botUserId := fmt.Sprintf("%x", id)

	// log.Println("Bot userid: ", botUserId)

	// Insert user into the database
	_, err = db.Exec("INSERT INTO users (id, admin) VALUES (?, 1)", botUserId)
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Parse the form
	err = r.ParseForm()
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	cloneid := r.PostFormValue("cloneid")

	if cloneid == "" {
		s, err := sessionStore.Get(r, "session")
		if err != nil {
			log.Println(err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		cloneid, _ = s.Values["userid"].(string)

		if cloneid == "" {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
	}

	// Call the bot
	data := struct {
		Actions []interface{} `json:"actions"`
		Browser string        `json:"browser"`
	}{
		Actions: []interface{}{
			map[string]string{
				"type": "request",
				"url":  CHALL_URL + "/login",
			},
			map[string]string{
				"type":    "type",
				"element": "#userid",
				"value":   botUserId,
			},
			map[string]string{
				"type":    "click",
				"element": "#submitbtn",
			},
			map[string]interface{}{
				"type": "sleep",
				"time": 1,
			},
			map[string]string{
				"type": "request",
				"url":  CHALL_URL + "/clone?cloneid=" + cloneid,
			},
			map[string]interface{}{
				"type": "sleep",
				"time": 1,
			},
			map[string]string{
				"type": "request",
				"url":  CHALL_URL + "/board?xray=1",
			},
			map[string]interface{}{
				"type": "sleep",
				"time": 4,
			},
		},
		Browser: "chrome",
	}

	dataJson, err := json.Marshal(data)
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("http://%s", HEADLESS_HOST), bytes.NewReader(dataJson))
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Auth", HEADLESS_AUTH)

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		log.Println(err)
		http.Error(w, "Something is wrong with the bot, please contact the admin", http.StatusInternalServerError)
		return
	}

	if res.StatusCode != 200 {
		http.Error(w, "Something is wrong with the bot, contact the admin", http.StatusInternalServerError)
		return
	}
	fmt.Fprint(w, "Ok")

}

func randInt(from int, to int) int {
	var n uint32
	err := binary.Read(rand.Reader, binary.LittleEndian, &n)
	if err != nil {
		log.Println(err)
	}

	x := from + int(n)%(to-from+1)

	return x
}

func GenerateBoard() []int {
	board := make([]int, DIM*DIM)

	firsBombX := randInt(0, 1) * (DIM - 1)
	firsBombY := randInt(0, 1) * (DIM - 1)

	firsBombInd := firsBombX*DIM + firsBombY

	board[firsBombInd] = 100

	// put bombs around the first bomb
	for i := 0; i < (DIM * DIM / 2); i++ {

		// get random position
		randPos := randInt(0, DIM*DIM-1)

		// check if the position is already a bomb
		if board[randPos] == 100 {
			i--
			continue
		}

		// check if the position is close to another bomb

		// get x and y of the random position
		randX := randPos / DIM
		randY := randPos % DIM

		// check up
		nearBomb := false

		if randX > 0 && board[randPos-DIM] == 100 {
			nearBomb = true
		}
		if randX < (DIM-1) && board[randPos+DIM] == 100 {
			nearBomb = true
		}
		if randY > 0 && board[randPos-1] == 100 {
			nearBomb = true
		}
		if randY < (DIM-1) && board[randPos+1] == 100 {
			nearBomb = true
		}

		if nearBomb {
			board[randPos] = 100
		} else {
			i--
		}
	}

	changed := true

	for changed {
		changed = false

		// Fill the rest of the board with the number of bombs around
		for i := 0; i < DIM*DIM; i++ {
			if board[i] == 100 {
				continue
			}

			x := i / DIM
			y := i % DIM

			count := 0

			if x > 0 {

				// check up
				if board[i-DIM] == 100 {
					count++
				}
				// check up left
				if y > 0 && board[i-(DIM+1)] == 100 {
					count++
				}
				// check up right
				if y < (DIM-1) && board[i-(DIM-1)] == 100 {
					count++
				}
			}
			if x < (DIM - 1) {

				// check down
				if board[i+DIM] == 100 {
					count++
				}
				// check down left
				if y > 0 && board[i+DIM-1] == 100 {
					count++
				}
				// check down right
				if y < (DIM-1) && board[i+DIM+1] == 100 {
					count++
				}
			}
			// check left
			if y > 0 && board[i-1] == 100 {
				count++
			}
			// check right
			if y < (DIM-1) && board[i+1] == 100 {
				count++
			}

			if count > 6 || ((y == 0 || y == (DIM-1) || x == 0 || x == (DIM-1)) && count > 3 || ((x == 0 || x == (DIM-1)) && (y == 0 || y == (DIM-1))) && count > 2) {
				// fmt.Println("Count: ", count)
				// fmt.Println("Pos: ", i)
				board[i] = 100
				changed = true
				break
			}

			board[i] = count
		}
	}

	bombs := 0
	for i := 0; i < DIM*DIM; i++ {
		if board[i] == 100 {
			bombs++
		}
	}

	// log.Printf("Generated board with %d%% bombs", bombs*100/(DIM*DIM))

	return board
}

func GenerateExploredBoard() []int {
	exploredBoard := make([]int, DIM*DIM)
	// fill with -1
	for i := range exploredBoard {
		exploredBoard[i] = -1
	}
	return exploredBoard
}

func DecodeBoard(boardJson string) []int {
	var board []int
	err := json.Unmarshal([]byte(boardJson), &board)
	if err != nil {
		log.Println(err)
	}
	return board
}

func EncodeBoard(board []int) string {
	boardJson, err := json.Marshal(board)
	if err != nil {
		log.Println(err)
	}
	return string(boardJson)
}
