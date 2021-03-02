# Welcome

This project is created to greeet our users!

    mvn clean install -Dmaven.test.skip

## places


| Description                           | location                          | should be visible for |
|:--------------------------------------|:----------------------------------|-----------------------| 
| Landing page                          | http://localhost:8080/home        | Anonym                |
| Greeter for every authenticated user  | http://localhost:8080/hello       | Logged in Users       |
| Admin-Greeter                         | http://localhost:8080/hello-admin | Only Admin            | 
| User-Greeter                          | http://localhost:8080/hello-user  | Users / Admin         |
| Login page                            | http://localhost:8080/login       | Anonym                |

## current Users

| Name  | Mail                | Password |
|-------|---------------------|----------|
| Alice | alice@example.local | 123456   |
| Bob   | bob@example.local   | password |
| Clyde | clyde@example.local | s3cr3t   |
       
## current Rolemapping

| User  | Role  |
|-------| ----- |     
| Alice | ADMIN | 
| Bob   | USER  | 
| Clyde | GUEST | 

 
## DB console

To access the database, I've put the endpoint in whitelist. You don't have to put in credentials ;)!!

    db jdbc:h2:mem:test

## the db console is here

    http://localhost:8080/h2-console

## TODO

There are still some challenges to resolve, the first 6 of them are:

| Task description                      | Challenge Hash                   | Points |
|---------------------------------------|:--------------------------------:|-------:|
| Admin cannot access user resource     | eb9b97d67e70c8868256b5d3e048d2ca |     1  |
| Improve Log/Audit                     | 4124bc0a9335c27f086f24ba207a4912 |     1  |
| Roles aren't working                  | 0cc175b9c0f1b6a831c399e269772661 |     2  |
| Encrypt Passwords                     | 838ece1033bf7c7468e873e79ba2a3ec |     3  |
| Introduce Salt                        | 3de47a0c26dcbfde469206be4bd55865 |     3  |
| Remove the Backdoor                   | d41d8cd98f00b204e9800998ecf8427e |     1  |
| New Session Identifier                | a424fec295f1efb97376e5d17138e5a1 |     2  |

PS: Points = difficulty, complexity