ALTER USER 'root'@'localhost' IDENTIFIED BY 'kajsdfouyhsdfhl';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost';
UPDATE mysql.user SET host='%' WHERE user='root';

CREATE USER 'ctf'@'%' IDENTIFIED WITH mysql_native_password BY 'kajsdfouyhsdfhl';
GRANT USAGE ON *.* TO 'ctf'@'%';
ALTER USER 'ctf'@'%' REQUIRE NONE WITH MAX_QUERIES_PER_HOUR 0 MAX_CONNECTIONS_PER_HOUR 0 MAX_UPDATES_PER_HOUR 0 MAX_USER_CONNECTIONS 0;
GRANT ALL PRIVILEGES ON `ctf`.* TO 'ctf'@'%';

FLUSH PRIVILEGES;

FLUSH PRIVILEGES;

CREATE DATABASE ctf;

USE ctf;

DROP TABLE IF EXISTS `users`;
CREATE TABLE users (
id INT AUTO_INCREMENT,
username varchar(50) NOT NULL,
password varchar(50) NOT NULL,
address TEXT NULL,
isPaid BOOLEAN NOT NULL,
locked BOOLEAN NOT NULL DEFAULT FALSE,
PRIMARY KEY (id),
UNIQUE (username)
);

INSERT INTO `users` (username, password, isPaid,locked)
VALUES ('admin','ajs09d7f8uy203ujlkvblckija97f633',FALSE,FALSE),
('test','test',FALSE,FALSE),
('michelle','0as8dyuflxkczjmvblxirfuaf971',TRUE, TRUE),
-- these two are the flag users
('mike','j9as7ya7a3636ncvx,jhj813298',TRUE, TRUE);

DELIMITER ;;

CREATE TRIGGER immutable BEFORE UPDATE ON users FOR EACH ROW
IF OLD.locked THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Why break it for everyone?';
END IF;;

CREATE TRIGGER undeletable BEFORE DELETE ON users FOR EACH ROW
IF OLD.locked THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Why break it for everyone?';
END IF;;

DELIMITER ;

DROP TABLE IF EXISTS `chats`;
CREATE TABLE chats (
reason varchar(250) NOT NULL,
visited BOOLEAN NOT NULL DEFAULT FALSE,
uuid varchar(250) NOT NULL,
PRIMARY KEY (uuid)
)

