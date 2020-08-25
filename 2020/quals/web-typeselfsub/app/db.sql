
DROP TABLE IF EXISTS `users`;
CREATE TABLE users (
id INT AUTO_INCREMENT,
username varchar(50) NOT NULL,
password varchar(50) NOT NULL,
address TEXT NULL,
PRIMARY KEY (id),
UNIQUE (username)
);

