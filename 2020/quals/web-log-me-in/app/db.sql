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
VALUES ('administrator','0as8dyuflxkczjmvblxirfuaf971',TRUE, TRUE),
('test','test',FALSE,FALSE),
('admin','admin',FALSE,FALSE),
('michelle','j9as7ya7a3636ncvx,jhj813298',TRUE, TRUE);
('mike','j9as7ya7a3636ncvx,jhj813298',TRUE, TRUE);


