# SecretsBox
SecretsBox is a web application that allows users to share and comment on secrets while maintaining their anonymity. It provides multiple OAuth mechanisms for user authentication, including Google, Facebook, and GitHub. No personal user details are displayed.

<br/><br/>

## Features
- User registration and login:
    - Users can create an account using their email and password.
    - Existing users can log in to their accounts securely.
- OAuth authentication:
    - Users can register/login using their Google, Facebook, or GitHub accounts.
- Anonymity:
    - User details are not displayed on the front end.
    - Users are identified by their usernames or OAuth provider IDs.
- Secret sharing:
    - Authenticated users can submit their secrets.
    - Secrets are associated with the respective users and stored securely.
- Commenting:
    - Authenticated users can comment on secrets.
    - Comments are associated with the corresponding secrets and users.

<br/><br/>

## Library Prerequisites
1. Express.js
2. Mongoose
3. Argon2
4. Crypto
5. Express-validator
6. Express-mongo-sanitize
7. CSurf
8. Helmet
9. Express-rate-limit
10. Cookie-parser
11. Passport
12. Passport-local
13. Passport-local-mongoose
14. Passport-google-oauth20
15. Passport-facebook
16. Passport-github2
17. Express-session
18. Mongoose-findorcreate
19. EJS (Embedded JavaScript) templating engine
20. Nodemon (optional)

You can install these dependencies using npm:
```bash
npm init

npm install express mongoose argon2 crypto express-validator express-mongo-sanitize csurf helmet express-rate-limit cookie-parser passport passport-local passport-google-oauth20 passport-facebook passport-github2 express-session mongoose-findorcreate passport-local-mongoose dotenv ejs

npm install nodemon -D
```

<br/><br/>

## Environment Variables
Create a *.env* file in the project root directory, refer to *.example-env*.

Add the following environment variables with their corresponding values:
- TIME_COST: Argon2 time cost parameter.
- MEMORY_COST: Argon2 memory cost parameter.
- PARALLELISM: Argon2 parallelism parameter.
- HASHLENGTH: Argon2 hash length parameter.
- SESSION_SECRET: Secret key for session management
- SECURE_COOKIE: true/false for enabling/disabling secure cookies for HTTPS
- GOOGLE_CLIENT_SECRET: Google OAuth client secret
- GOOGLE_REDIRECT_URI: Google OAuth redirect URI
- FACEBOOK_APP_ID: Facebook OAuth app ID
- FACEBOOK_APP_SECRET: Facebook OAuth app secret
- FACEBOOK_REDIRECT_URI: Facebook OAuth redirect URI
- GITHUB_CLIENT_ID: GitHub OAuth client ID
- GITHUB_CLIENT_SECRET: GitHub OAuth client secret
- GITHUB_REDIRECT_URI: GitHub OAuth redirect URI

<br/><br/>

## Connect to Database
Unstall MongoDB directly on your local machine or a server within your own infrastructure. You start a MongoDB server instance on that machine, and your application can connect to the MongoDB server using the appropriate connection parameters (mongodb://localhost:`<port>`/`<database-name>`). Click [here](https://www.mongodb.com/docs/manual/) to read the MongoDB documentation. You can either use [MongoDb Shell (mongosh)](https://www.mongodb.com/docs/mongodb-shell/) or [MongoDB Compass](https://www.mongodb.com/docs/compass/current/) (Recommended) to connect server.

<br/><br/>

## Starting localhost
To run your Node.js application on localhost, follow these steps:
1. Open your terminal or command prompt and navigate to the directory where your app.js file is located.
2. Run the following command to start the application:
    ```bash
    node app.js
    ```
    This will start your Node.js application, and it will be accessible at http://localhost:3000 (3000 or whichever port is specified).

**OR** (Recommended)

1. Update the package.json file by setting the "main" property to "app.js":
    ```json
    {
      ...
      "main": "app.js",
      ...
    }
    ```

2. To avoid the need to manually stop and restart a Node.js application every time a change is made to the code, nodemon should be used. Open your terminal/command prompt in that directory and run the following command:
    ```bash
    nodemon
    ```
    Nodemon will monitor your files for changes, and it will automatically restart the application whenever a change is detected. This saves you time and effort, allowing you to focus on writing code and testing it without the need for manual application restarts.

<br/><br/>

## Demonstartion
| ![Imgur](https://i.imgur.com/AmvjqX9.gif) |
|:--:|
| <i>Demo</i> |