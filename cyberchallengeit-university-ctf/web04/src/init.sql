SET
	NAMES 'utf8mb4';

SET
	CHARACTER SET utf8mb4;

CREATE TABLE IF NOT EXISTS users (
	id INT AUTO_INCREMENT PRIMARY KEY,
	username VARCHAR(255) NOT NULL UNIQUE,
	is_public BOOLEAN DEFAULT FALSE,
	password VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS posts (
	id INT AUTO_INCREMENT PRIMARY KEY,
	user_id INT NOT NULL,
	description TEXT NOT NULL,
	picture VARCHAR(255) NOT NULL,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS secrets (flag VARCHAR(255) PRIMARY KEY);

INSERT INTO
	users (username, password, is_public)
VALUES
	("sir_meowsalot", MD5(UUID()), TRUE),
	("queen_mittens", MD5(UUID()), TRUE),
	("mr_whiskersworth", MD5(UUID()), TRUE),
	("princess_purrington", MD5(UUID()), TRUE),
	("captain_catnip", MD5(UUID()), TRUE),
	("duke_fuzzypaws", MD5(UUID()), TRUE);

INSERT INTO
	posts (user_id, description, picture, created_at)
VALUES
	(
		1,
		"Those eyes though! Can't resist the charm of my feline friend. 🐾 #CatLove #Purrfection",
		"e20f5c02-a867-4745-b739-34b7b4f14e1c",
		CURRENT_TIMESTAMP - INTERVAL 1 HOUR
	),
	(
		2,
		"Double the snuggles, double the love! Caught these two cuddle buddies sharing a purr-fect moment together. 💕🐾 #CuddleBuddies #CatLove #SnuggleSesh",
		"6ae3970f-da20-4005-8080-b7dbb3a10695",
		CURRENT_TIMESTAMP - INTERVAL 1.5 HOUR
	),
	(
		3,
		"Elegance in every whisker! Captured the timeless beauty of this majestic feline in a purr-fectly poised moment. 📸😺 #CatPortrait #FelineElegance #ProfessionalCatography",
		"05bbebad-1a73-4216-a0cc-3abf8bc0f075",
		CURRENT_TIMESTAMP - INTERVAL 2 HOUR
	),
	(
		4,
		"Sweet dreams in progress! Caught my furry friend indulging in a blissful catnap. 😴💤 #CatNap #SweetDreams #SleepingBeauty",
		"3294863e-8f66-4a90-a327-812d869cea99",
		CURRENT_TIMESTAMP - INTERVAL 2.3 HOUR
	),
	(
		5,
		"Caught mid-game snooze! Looks like someone played fetch a bit too hard. 🎾😸 #CatNap #TennisBallDreams #PlayHardSleepHard",
		"d3aa5acc-1613-4193-bb2e-e93d9d15d59a",
		CURRENT_TIMESTAMP - INTERVAL 2.9 HOUR
	),
	(
		6,
		"Quadruple the cuteness! These four bundles of fur have claimed the sofa as their kingdom. 🐾💕 #KittenCuddle #SofaSquad #FurFamily",
		"5bbf5b39-7516-4260-899b-ad4a4689fcac",
		CURRENT_TIMESTAMP - INTERVAL 3.6 HOUR
	);

INSERT INTO
	secrets (flag)
VALUES
	(
		'CCIT{Why_th3_H3ck_1s_th1S_4_d3f4Ult_B3h4v10uR_a23540a5}'
	);

/* some hardening to avoid DoSsing */
REVOKE ALL PRIVILEGES ON *.*
FROM
	`sharepic` @`%`;

REVOKE ALL PRIVILEGES ON `sharepic`.*
FROM
	`sharepic` @`%`;

GRANT
SELECT
	ON `sharepic`.* TO `sharepic` @`%`;

GRANT
INSERT
	ON `sharepic`.`users` TO `sharepic` @`%`;

GRANT
INSERT
	ON `sharepic`.`posts` TO `sharepic` @`%`;