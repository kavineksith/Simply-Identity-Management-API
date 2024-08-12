## **Simply Identity Management API Documentation**

### Overview

This document provides comprehensive documentation for an API and its associated database. The API facilitates user authentication and management, while the database stores authentication credentials and user information. This documentation adheres to industrial standards to ensure clarity, reliability, and security.

### Installation Steps

1. Install the required dependencies by running `npm install`.
   ```
   npm install
   ```

2. Database Initialization
   - Ensure SQLite is installed on your system.
   - Run the following command to initialize the database:
     ```
     node database.js
     ```

3. Start the server by running `node app.js`.
   ```
   node app.js
   ```

### Used Technologies

- Node JS Runtime Environment
- Express JS Framework
- SQLite3 Database

### API Documentation

#### Base URL

The base URL for this API is `http://localhost:8080/`.

#### Authentication

- **JWT Tokens:** Authentication is achieved using JWT tokens. Users obtain tokens by logging in with valid API keys and secret keys.

#### Rate Limiting

- **Rate Limit:** Requests to this API are rate-limited to 100 requests per 15 minutes per IP address.

#### Security

- **CORS Headers:** Cross-Origin Resource Sharing (CORS) headers are implemented to secure communication between the client and server.
- **Helmet Middleware:** Basic security headers are applied using the Helmet middleware.
- **Rate Limiting:** Rate limiting prevents abuse and ensures fair usage of the API.

#### Error Handling

- **Error Responses:** Standard HTTP status codes are utilized for error handling to provide clear feedback to clients.

#### Endpoints

1. **Generate API Keys and Secret Keys**
   - **URL:** `/generate-keys`
   - **Method:** `GET`
   - **Description:** Generates API keys and secret keys for authentication purposes.

2. **User Login**
   - **URL:** `/login`
   - **Method:** `POST`
   - **Description:** Issues a JWT token upon successful authentication with valid API key and secret key.

3. **Create User**
   - **URL:** `/users/insert/`
   - **Method:** `POST`
   - **Description:** Creates a new user record.

4. **Read All Users**
   - **URL:** `/users/view/`
   - **Method:** `GET`
   - **Description:** Retrieves information of all users.

5. **Read User by ID**
   - **URL:** `/users/view/:id`
   - **Method:** `GET`
   - **Description:** Retrieves information of a user by their ID.

6. **Update User**
   - **URL:** `/users/modify/:id`
   - **Method:** `PUT`
   - **Description:** Updates information of an existing user.

7. **Delete User**
   - **URL:** `/users/:id`
   - **Method:** `DELETE`
   - **Description:** Deletes a user by their ID.

#### Security Considerations

- **JWT Tokens:** Ensure secure storage and transmission of JWT tokens to prevent unauthorized access.
- **API Keys and Secret Keys:** Safeguard API keys and secret keys to prevent unauthorized API access.
- **HTTPS:** Deploy the API behind HTTPS to encrypt data in transit.

---

### Database Documentation

#### Overview

The database stores authentication management and user information for the API. It consists of two main tables: `api_keys` for authentication keys and `users` for user details.

#### Database Initialization

- **SQLite Database:** The database is implemented using SQLite3.
- **Connection:** The database connection is established with the `mydatabase.db` file.

#### Tables

1. **Table: `api_keys`**
   - **Fields:** `id`, `api_key`, `secret_key`
   - **Purpose:** Stores API keys and secret keys for authentication.

2. **Table: `users`**
   - **Fields:** `userID`, `fname`, `lname`, `dateOfBirth`, `address`, `emailAddress`, `contactNumber`, `country`
   - **Purpose:** Stores user information.

#### Initialization Process

- During initialization, the database checks for table existence and creates them if necessary.

#### Error Handling

- Errors during database initialization or table creation are logged to the console.

---

### License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

### Conclusion

This documentation adheres to industrial standards to ensure clarity, reliability, and security in API and database operations. Kindly note that this project is developed solely for educational purposes, not intended for industrial use, as its sole intention lies within the realm of education. We emphatically underscore that this endeavor is not sanctioned for industrial application. It is imperative to bear in mind that any utilization of this project for commercial endeavors falls outside the intended scope and responsibility of its creators. Thus, we explicitly disclaim any liability or accountability for such usage.
