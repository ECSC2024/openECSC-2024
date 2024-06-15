USE not_phishing;

CREATE TABLE IF NOT EXISTS `users`(
    `id` INT NOT NULL AUTO_INCREMENT,
    `email` VARCHAR(200) NOT NULL,
    `username` VARCHAR(200) NOT NULL,
    `password` CHAR(64) NOT NULL,
    `verified` BOOLEAN NOT NULL DEFAULT FALSE,
    `verification_token` CHAR(64) DEFAULT NULL,
    `is_admin` BOOLEAN NOT NULL DEFAULT FALSE,

    PRIMARY KEY (`id`)
) CHARACTER SET=utf8mb4;

CREATE TABLE login_token(
    `id` INT NOT NULL AUTO_INCREMENT,
    `user_id` INT NOT NULL,
    `token` CHAR(64) DEFAULT NULL,

    PRIMARY KEY (`id`),
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`)
);


INSERT INTO `users` (`email`, `username`, `password`, `verified`, `is_admin`) VALUES ('admin@fakemail.olicyber.it', 'admin', '', TRUE, TRUE);
