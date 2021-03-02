DROP TABLE IF EXISTS ACCOUNT_ROLE;
DROP TABLE IF EXISTS ACCOUNTS;
DROP TABLE IF EXISTS ROLES;
DROP SEQUENCE IF EXISTS ACCOUNT_SEQ;

CREATE SEQUENCE ACCOUNT_SEQ START WITH 100 INCREMENT BY 5;

CREATE TABLE ROLE (
    rolename varchar(50) PRIMARY KEY
);

CREATE TABLE ACCOUNT (
  id INT AUTO_INCREMENT  PRIMARY KEY,
  name VARCHAR(250) NOT NULL,
  mail VARCHAR(250) NOT NULL,
  pw VARCHAR(250) DEFAULT NULL
);

CREATE TABLE ACCOUNT_ROLE (
  account_id INT not null,
  role_id varchar(50) not null,
  foreign key (account_id) references account (id),
  foreign key (role_id) references role (rolename)
);

INSERT INTO ACCOUNT (name, mail, pw) VALUES
  ('Alice', 'alice@example.local', '123456'),
  ('Bob', 'bob@example.local', 'password'),
  ('Clyde', 'clyde@example.local', 's3cr3t');


INSERT INTO ROLE (rolename) VALUES ('ADMIN');
INSERT INTO ROLE (rolename) VALUES ('GUEST');
INSERT INTO ROLE (rolename) VALUES ('USER');

INSERT INTO ACCOUNT_ROLE (account_id, role_id) VALUES (1, 'ADMIN');
INSERT INTO ACCOUNT_ROLE (account_id, role_id) VALUES (2, 'USER');
INSERT INTO ACCOUNT_ROLE (account_id, role_id) VALUES (3, 'GUEST');